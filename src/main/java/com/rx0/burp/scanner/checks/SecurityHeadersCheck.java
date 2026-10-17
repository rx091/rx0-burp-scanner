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

/**
 * Verifica a ausência de headers de segurança importantes na resposta HTTP.
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class SecurityHeadersCheck implements VulnCheck {

    @Override
    public String nome() {
        return "Headers de segurança";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return achados;

            checarAusencia(achados, resp, baseUrl, "Content-Security-Policy", Severity.MEDIA,
                    "Ausência de Content-Security-Policy (CSP)",
                    "Sem CSP o navegador não limita a origem de scripts/estilos, facilitando XSS e injeção de conteúdo.",
                    "Defina uma política CSP restritiva (default-src 'self' e exceções mínimas necessárias).");

            checarAusencia(achados, resp, baseUrl, "X-Frame-Options", Severity.MEDIA,
                    "Ausência de X-Frame-Options",
                    "O site pode ser carregado dentro de um <iframe> de terceiros, abrindo brecha para clickjacking.",
                    "Adicione X-Frame-Options: DENY ou SAMEORIGIN (ou frame-ancestors via CSP).");

            checarAusencia(achados, resp, baseUrl, "Strict-Transport-Security", Severity.MEDIA,
                    "Ausência de HSTS (Strict-Transport-Security)",
                    "Sem HSTS, conexões podem ser forçadas para HTTP, abrindo brecha para downgrade/MITM.",
                    "Adicione Strict-Transport-Security: max-age=31536000; includeSubDomains.");

            checarAusencia(achados, resp, baseUrl, "X-Content-Type-Options", Severity.BAIXA,
                    "Ausência de X-Content-Type-Options",
                    "Sem esse header, navegadores antigos podem tentar 'adivinhar' o tipo de conteúdo (MIME sniffing).",
                    "Adicione X-Content-Type-Options: nosniff.");

            checarAusencia(achados, resp, baseUrl, "Referrer-Policy", Severity.BAIXA,
                    "Ausência de Referrer-Policy",
                    "Sem essa política, a URL completa pode vazar para terceiros via header Referer.",
                    "Adicione Referrer-Policy: strict-origin-when-cross-origin (ou mais restritiva).");

            checarAusencia(achados, resp, baseUrl, "Permissions-Policy", Severity.INFO,
                    "Ausência de Permissions-Policy",
                    "Sem essa política, o navegador não restringe o uso de APIs sensíveis (câmera, geolocalização, etc).",
                    "Defina Permissions-Policy limitando as features realmente necessárias.");

            // Banners de tecnologia que facilitam fingerprinting
            for (HttpHeader h : resp.headers()) {
                String name = h.name();
                if (name.equalsIgnoreCase("Server") || name.equalsIgnoreCase("X-Powered-By")) {
                    achados.add(new Finding(
                            "Divulgação de tecnologia via header " + name,
                            Severity.INFO,
                            baseUrl,
                            "O header '" + name + "' expõe informação sobre a stack do servidor: " + h.value(),
                            name + ": " + h.value(),
                            "Remova ou mascare esse header no servidor web / proxy reverso."
                    ));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro no check de headers: " + e.getMessage());
        }
        return achados;
    }

    private void checarAusencia(List<Finding> achados, HttpResponse resp, String url, String headerName,
                                 Severity sev, String titulo, String descricao, String recomendacao) {
        boolean presente = resp.headers().stream().anyMatch(h -> h.name().equalsIgnoreCase(headerName));
        if (!presente) {
            achados.add(new Finding(titulo, sev, url, descricao, "Header '" + headerName + "' não encontrado na resposta.", recomendacao));
        }
    }
}
