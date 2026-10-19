package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cliente do protocolo interactsh (https://github.com/projectdiscovery/interactsh) —
 * implementação própria em Java puro (sem biblioteca externa), usada pela extensão
 * para confirmação OUT-OF-BAND (OOB) de vulnerabilidades que não deixam rastro na
 * resposta HTTP direta (SSRF, RFI, XXE via SSRF, OS Command Injection blind).
 *
 * Como funciona, resumidamente:
 *  1) Gera um par de chaves RSA-2048 e registra no servidor interactsh (register)
 *  2) Pra cada teste, gera um subdomínio ÚNICO que aponta pro servidor interactsh
 *     e embute esse subdomínio no payload de teste (ex: SSRF apontando pra ele)
 *  3) Depois de todos os checks rodarem, espera alguns segundos e consulta o
 *     servidor (poll) — se o alvo realmente "ligou de volta" pro nosso domínio
 *     (DNS lookup ou requisição HTTP), isso confirma a vulnerabilidade de forma
 *     inequívoca, sem depender de reflexão de conteúdo ou timing.
 *  4) As interações retornam criptografadas (AES-256, com a chave AES protegida
 *     por RSA-OAEP-SHA256) — decriptografamos com nossa chave privada.
 *
 * Se o registro falhar por qualquer motivo (rede bloqueada, servidor indisponível),
 * isDisponivel() retorna false e todo o resto da extensão continua funcionando
 * normalmente, só sem o bônus de confirmação OOB — é estritamente aditivo.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class InteractshClient {

    private static final String[] SERVIDORES_PUBLICOS = {"oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun"};
    private static final String ALFABETO = "abcdefghijklmnopqrstuvwxyz0123456789";

    private final MontoyaApi api;
    private final String servidor;
    private final String correlationId;
    private final String secretKey;
    private final PrivateKey chavePrivada;
    private final boolean disponivel;

    private final List<ProbeRegistrado> probesRegistrados = Collections.synchronizedList(new ArrayList<>());

    private InteractshClient(MontoyaApi api, String servidor, String correlationId, String secretKey,
                              PrivateKey chavePrivada, boolean disponivel) {
        this.api = api;
        this.servidor = servidor;
        this.correlationId = correlationId;
        this.secretKey = secretKey;
        this.chavePrivada = chavePrivada;
        this.disponivel = disponivel;
    }

    /** Tenta registrar com um dos servidores públicos interactsh. Nunca lança exceção. */
    public static InteractshClient iniciar(MontoyaApi api) {
        try {
            KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
            gerador.initialize(2048);
            KeyPair par = gerador.generateKeyPair();

            String correlationId = idAleatorio(20);
            String secretKey = UUID.randomUUID().toString();
            String chavePublicaB64 = exportarChavePublicaBase64(par.getPublic());

            for (String servidor : SERVIDORES_PUBLICOS) {
                try {
                    String corpo = "{\"public-key\":\"" + chavePublicaB64 + "\",\"secret-key\":\"" + secretKey
                            + "\",\"correlation-id\":\"" + correlationId + "\"}";
                    HttpRequest req = HttpRequest.httpRequestFromUrl("https://" + servidor + "/register")
                            .withMethod("POST")
                            .withAddedHeader("Content-Type", "application/json")
                            .withBody(corpo);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp != null && resp.statusCode() == 200) {
                        api.logging().logToOutput("[Rx0] Interactsh (confirmação OOB) registrado com sucesso em " + servidor
                                + " — SSRF/RFI/XXE/OS Command Injection terão confirmação adicional quando houver interação real.");
                        return new InteractshClient(api, servidor, correlationId, secretKey, par.getPrivate(), true);
                    }
                } catch (Exception ignorado) {
                    // tenta o próximo servidor da lista
                }
            }
            api.logging().logToOutput("[Rx0] Não foi possível registrar com nenhum servidor interactsh público — " +
                    "os checks de OOB continuam funcionando normalmente, só sem a confirmação adicional out-of-band.");
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro ao iniciar cliente interactsh: " + e.getMessage());
        }
        return new InteractshClient(api, null, null, null, null, false);
    }

    public boolean isDisponivel() {
        return disponivel;
    }

    /**
     * Gera um host único (ex: "ab3f...xyz.oast.pro") e registra internamente a que
     * achado ele corresponde, para o caso de uma interação real chegar depois.
     * @return o host gerado, ou null se o cliente não está disponível.
     */
    public String criarProbe(String titulo, Severity severidade, String url, String descricao,
                              String recomendacao, String modoExploracao) {
        if (!disponivel) return null;
        String sufixo = idAleatorio(13);
        String idUnico = sufixo + correlationId;
        String host = idUnico + "." + servidor;
        probesRegistrados.add(new ProbeRegistrado(idUnico, titulo, severidade, url, descricao, recomendacao, modoExploracao));
        return host;
    }

    /**
     * Espera alguns segundos (pra dar tempo do alvo processar o payload e tentar
     * contatar o host gerado) e consulta o servidor interactsh por interações.
     * Deve ser chamado UMA VEZ, no final do scan inteiro (depois de todos os
     * checks terem disparado seus payloads).
     */
    public List<Finding> aguardarEColetarInteracoes(int segundosEspera) {
        List<Finding> achados = new ArrayList<>();
        if (!disponivel || probesRegistrados.isEmpty()) return achados;

        try {
            Thread.sleep(segundosEspera * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return achados;
        }

        try {
            String url = "https://" + servidor + "/poll?id=" + correlationId + "&secret=" + secretKey;
            HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
            if (resp == null || resp.statusCode() != 200) return achados;

            String corpo = resp.bodyToString();
            if (corpo == null) return achados;

            String aesKeyB64 = extrairCampoJson(corpo, "aes_key");
            List<String> dados = extrairArrayJson(corpo, "data");
            if (aesKeyB64 == null || dados.isEmpty()) return achados;

            byte[] chaveAes = descriptografarChaveAes(aesKeyB64);

            for (String itemB64 : dados) {
                try {
                    String jsonInteracao = descriptografarInteracao(itemB64, chaveAes);
                    String fullId = extrairCampoJson(jsonInteracao, "full-id");
                    if (fullId == null) fullId = extrairCampoJson(jsonInteracao, "unique-id");
                    String protocolo = extrairCampoJson(jsonInteracao, "protocol");
                    String enderecoRemoto = extrairCampoJson(jsonInteracao, "remote-address");

                    ProbeRegistrado probe = encontrarProbe(fullId);
                    if (probe != null) {
                        achados.add(new Finding(
                                probe.titulo + " — CONFIRMADO via interação out-of-band (" + protocolo + ")",
                                probe.severidade,
                                probe.url,
                                probe.descricao + " Confirmação adicional: o servidor alvo efetivamente contatou nossa " +
                                        "infraestrutura de teste via protocolo " + protocolo + " (origem: " + enderecoRemoto +
                                        "). Essa é uma confirmação out-of-band inequívoca, independente de reflexão de " +
                                        "conteúdo na resposta — o host alvo processou o payload e tentou alcançar um " +
                                        "destino externo que só existe porque nós o criamos para este teste.",
                                "Interação OOB recebida via interactsh: protocolo=" + protocolo + " | origem=" + enderecoRemoto
                                        + " | id=" + fullId,
                                probe.recomendacao,
                                probe.modoExploracao));
                    }
                } catch (Exception eInterna) {
                    api.logging().logToError("[Rx0] Erro ao decodificar interação OOB: " + eInterna.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro ao consultar (poll) o servidor interactsh: " + e.getMessage());
        }
        return achados;
    }

    private ProbeRegistrado encontrarProbe(String fullId) {
        if (fullId == null) return null;
        for (ProbeRegistrado p : probesRegistrados) {
            if (fullId.startsWith(p.idUnico) || p.idUnico.startsWith(fullId)) return p;
        }
        return null;
    }

    // ---------- Criptografia ----------

    private byte[] descriptografarChaveAes(String aesKeyB64) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec params = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, chavePrivada, params);
        return cipher.doFinal(Base64.getDecoder().decode(aesKeyB64));
    }

    private String descriptografarInteracao(String itemB64, byte[] chaveAes) throws Exception {
        byte[] bruto = Base64.getDecoder().decode(itemB64);
        byte[] iv = Arrays.copyOfRange(bruto, 0, 16);
        byte[] cifrado = Arrays.copyOfRange(bruto, 16, bruto.length);
        Cipher cipher = Cipher.getInstance("AES/CFB128/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chaveAes, "AES"), new IvParameterSpec(iv));
        return new String(cipher.doFinal(cifrado), StandardCharsets.UTF_8);
    }

    private static String exportarChavePublicaBase64(PublicKey chave) {
        byte[] der = chave.getEncoded();
        String b64Linhas = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der);
        String pem = "-----BEGIN PUBLIC KEY-----\n" + b64Linhas + "\n-----END PUBLIC KEY-----\n";
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    private static String idAleatorio(int tamanho) {
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(tamanho);
        for (int i = 0; i < tamanho; i++) {
            sb.append(ALFABETO.charAt(rnd.nextInt(ALFABETO.length())));
        }
        return sb.toString();
    }

    // ---------- Parsing JSON manual (sem dependência externa) ----------

    private static String extrairCampoJson(String json, String campo) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(campo) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static List<String> extrairArrayJson(String json, String campo) {
        List<String> itens = new ArrayList<>();
        Matcher m = Pattern.compile("\"" + Pattern.quote(campo) + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(json);
        if (m.find()) {
            Matcher itemMatcher = Pattern.compile("\"([^\"]*)\"").matcher(m.group(1));
            while (itemMatcher.find()) itens.add(itemMatcher.group(1));
        }
        return itens;
    }

    /** Metadados de um probe OOB pendente, aguardando confirmação via poll. */
    private static class ProbeRegistrado {
        final String idUnico;
        final String titulo;
        final Severity severidade;
        final String url;
        final String descricao;
        final String recomendacao;
        final String modoExploracao;

        ProbeRegistrado(String idUnico, String titulo, Severity severidade, String url,
                         String descricao, String recomendacao, String modoExploracao) {
            this.idUnico = idUnico;
            this.titulo = titulo;
            this.severidade = severidade;
            this.url = url;
            this.descricao = descricao;
            this.recomendacao = recomendacao;
            this.modoExploracao = modoExploracao;
        }
    }
}
