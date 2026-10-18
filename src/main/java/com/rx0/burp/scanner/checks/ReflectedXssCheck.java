package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/**
 * Injeta marcadores únicos em parâmetros de QUERY e também no CORPO
 * (JSON e form-urlencoded) de requisições POST, testando vários contextos
 * de payload (tag HTML crua, atributo, dentro de script), e verifica se o
 * payload volta SEM escaping na resposta — indicando possível XSS refletido.
 *
 * Apenas um probe não-intrusivo (não executa o JS de verdade) — não
 * confirma exploração real, mas é um sinal forte de ausência de encoding
 * de saída.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class ReflectedXssCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {
            "q", "search", "s", "query", "name", "id", "redirect", "url",
            "comment", "message", "title", "description", "tag", "keyword"
    };

    private static final String MARCADOR = "rx0" + (System.currentTimeMillis() % 100000);

    // Payloads em contextos diferentes: tag crua, quebra de atributo, quebra de script
    private static final String[] PAYLOADS = {
            "<rx0xss>" + MARCADOR + "</rx0xss>",
            "\"><rx0xss " + MARCADOR + "=1>",
            "'><rx0xss " + MARCADOR + "=1>",
            "</script><rx0xss>" + MARCADOR + "</rx0xss><script>",
            "<img src=x onerror=rx0_" + MARCADOR + "()>",
            "<svg onload=rx0_" + MARCADOR + "()>",
    };

    @Override
    public String nome() {
        return "XSS refletido (GET + POST, múltiplos contextos)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        achados.addAll(testarViaQueryString(api, base));
        achados.addAll(testarViaCorpoJson(api, base));
        achados.addAll(testarViaCorpoFormUrlEncoded(api, base));

        return achados;
    }

    private List<Finding> testarViaQueryString(MontoyaApi api, String base) {
        List<Finding> achados = new ArrayList<>();
        for (String param : PARAM_NAMES) {
            for (String payload : PAYLOADS) {
                try {
                    String testUrl = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                    HttpRequest req = HttpRequest.httpRequestFromUrl(testUrl);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body != null && body.contains(payload)) {
                        achados.add(construirFinding(param, testUrl, payload, "query string (GET)"));
                        break; // já confirmado nesse param, pula pros outros payloads
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro no XSS GET (param " + param + "): " + e.getMessage());
                }
            }
        }
        return achados;
    }

    private List<Finding> testarViaCorpoJson(MontoyaApi api, String base) {
        List<Finding> achados = new ArrayList<>();
        String[] paths = {"/api/comments", "/api/search", "/api/feedback", "/api/contact"};
        for (String path : paths) {
            for (String param : new String[]{"comment", "message", "name", "search", "content"}) {
                try {
                    String payload = PAYLOADS[0];
                    String corpo = "{\"" + param + "\":\"" + payload.replace("\"", "\\\"") + "\"}";
                    HttpRequest req = HttpRequest.httpRequestFromUrl(base + path)
                            .withMethod("POST")
                            .withAddedHeader("Content-Type", "application/json")
                            .withBody(corpo);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body != null && body.contains(payload)) {
                        achados.add(construirFinding(param, base + path, payload, "corpo JSON (POST)"));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro no XSS JSON (" + path + "/" + param + "): " + e.getMessage());
                }
            }
        }
        return achados;
    }

    private List<Finding> testarViaCorpoFormUrlEncoded(MontoyaApi api, String base) {
        List<Finding> achados = new ArrayList<>();
        String[] paths = {"/search", "/comment", "/contact", "/feedback"};
        for (String path : paths) {
            for (String param : new String[]{"q", "comment", "message", "name"}) {
                try {
                    String payload = PAYLOADS[0];
                    String corpo = param + "=" + URLEncoder.encode(payload, "UTF-8");
                    HttpRequest req = HttpRequest.httpRequestFromUrl(base + path)
                            .withMethod("POST")
                            .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                            .withBody(corpo);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body != null && body.contains(payload)) {
                        achados.add(construirFinding(param, base + path, payload, "corpo form-urlencoded (POST)"));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro no XSS form (" + path + "/" + param + "): " + e.getMessage());
                }
            }
        }
        return achados;
    }

    private Finding construirFinding(String param, String url, String payload, String origem) {
        return new Finding(
                "Possível XSS refletido no parâmetro '" + param + "' via " + origem,
                Severity.ALTA,
                url,
                "O payload de teste foi refletido na resposta sem escaping, indicando ausência de sanitização/encoding de saída " +
                        "nesse ponto da aplicação (origem: " + origem + ").",
                "Payload: " + payload + " | Encontrado verbatim na resposta.",
                "Faça encoding de saída (HTML entity encoding) de qualquer dado refletido no HTML, valide o Content-Type da resposta, " +
                        "e implemente CSP como defesa em profundidade.",
                "1) Abra a URL em um navegador: " + url + " 2) Se o payload de teste (<rx0xss>) não executou por ser uma tag " +
                        "inofensiva, troque por um payload de PoC real, ex: <script>alert(document.cookie)</script> ou " +
                        "<img src=x onerror=alert(document.domain)> no mesmo parâmetro '" + param + "'. 3) Confirme a execução do " +
                        "JavaScript (popup do alert) no navegador. 4) Para impacto real, demonstre roubo de cookie/sessão " +
                        "redirecionando document.cookie para um listener controlado (ex: webhook.site) — sempre documentando como PoC, nunca em produção real sem autorização específica para isso.");
    }
}
