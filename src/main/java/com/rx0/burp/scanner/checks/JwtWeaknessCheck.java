package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

                    analisarToken(achados, token, item.finalRequest().url());
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro ao processar item do histórico de proxy: " + e.getMessage());
            }
        }
        return achados;
    }

    private void analisarToken(List<Finding> achados, String token, String urlOrigem) {
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
                    "Nunca aceite tokens com alg=none. Force a verificação de um algoritmo específico (ex: RS256) no backend."));
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
