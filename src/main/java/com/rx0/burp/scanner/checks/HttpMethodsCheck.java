package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Verifica métodos HTTP perigosos habilitados no servidor:
 *  - TRACE habilitado (Cross-Site Tracing / XST)
 *  - Allow header (via OPTIONS) expondo PUT/DELETE sem autenticação aparente
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class HttpMethodsCheck implements VulnCheck {

    @Override
    public String nome() {
        return "Métodos HTTP perigosos (TRACE/PUT/DELETE)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();

        // 1) OPTIONS — ver o que o servidor diz que é permitido
        try {
            HttpRequest optionsReq = HttpRequest.httpRequestFromUrl(baseUrl).withMethod("OPTIONS");
            HttpResponse optionsResp = api.http().sendRequest(optionsReq).response();
            if (optionsResp != null) {
                Optional<HttpHeader> allow = optionsResp.headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Allow") || h.name().equalsIgnoreCase("Access-Control-Allow-Methods"))
                        .findFirst();
                if (allow.isPresent()) {
                    String valor = allow.get().value().toUpperCase();
                    if (valor.contains("PUT") || valor.contains("DELETE") || valor.contains("PATCH")) {
                        achados.add(new Finding(
                                "Métodos de escrita expostos via " + allow.get().name(),
                                Severity.BAIXA,
                                baseUrl,
                                "O servidor anuncia suportar métodos de escrita/alteração (PUT/DELETE/PATCH) nessa rota raiz. " +
                                        "Isso não é necessariamente uma falha, mas vale confirmar se esses métodos exigem autenticação " +
                                        "adequada quando usados em endpoints de API reais.",
                                allow.get().name() + ": " + allow.get().value(),
                                "Garanta que todo método de escrita exija autenticação e autorização, e desabilite métodos não usados."));
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro ao checar OPTIONS: " + e.getMessage());
        }

        // 2) TRACE — Cross-Site Tracing (XST)
        try {
            String marcador = "Rx0-XST-Test: " + System.currentTimeMillis();
            HttpRequest traceReq = HttpRequest.httpRequestFromUrl(baseUrl)
                    .withMethod("TRACE")
                    .withAddedHeader("X-Rx0-Marker", marcador);
            HttpResponse traceResp = api.http().sendRequest(traceReq).response();
            if (traceResp != null && traceResp.statusCode() == 200) {
                String body = traceResp.bodyToString();
                if (body != null && body.contains("X-Rx0-Marker")) {
                    achados.add(new Finding(
                            "Método TRACE habilitado (Cross-Site Tracing)",
                            Severity.MEDIA,
                            baseUrl,
                            "O servidor aceita requisições TRACE e reflete os headers enviados de volta no corpo da resposta. " +
                                    "Combinado com XSS, isso pode ser usado para roubar cookies HttpOnly via Cross-Site Tracing (XST).",
                            "Header de marcação refletido na resposta do TRACE.",
                            "Desabilite o método TRACE (e TRACK) no servidor web."));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro ao checar TRACE: " + e.getMessage());
        }

        return achados;
    }
}
