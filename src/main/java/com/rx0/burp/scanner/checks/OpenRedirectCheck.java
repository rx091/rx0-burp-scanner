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
 * Testa parâmetros comuns de redirecionamento com uma URL externa forjada
 * e verifica se o servidor redireciona (3xx + Location) para ela.
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class OpenRedirectCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"redirect", "redirect_uri", "url", "next", "return", "returnUrl", "continue", "dest"};
    private static final String DOMINIO_EXTERNO = "rx0-redirect-test.evil.example";

    @Override
    public String nome() {
        return "Open Redirect";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            try {
                String payload = "https://" + DOMINIO_EXTERNO;
                String testUrl = base + "/?" + param + "=" + java.net.URLEncoder.encode(payload, "UTF-8");
                HttpRequest req = HttpRequest.httpRequestFromUrl(testUrl);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                int status = resp.statusCode();
                if (status >= 300 && status < 400) {
                    Optional<HttpHeader> location = resp.headers().stream()
                            .filter(h -> h.name().equalsIgnoreCase("Location"))
                            .findFirst();
                    if (location.isPresent() && location.get().value().contains(DOMINIO_EXTERNO)) {
                        achados.add(new Finding(
                                "Possível Open Redirect no parâmetro '" + param + "'",
                                Severity.MEDIA,
                                testUrl,
                                "A aplicação redirecionou (HTTP " + status + ") para um domínio externo controlado a partir do valor do parâmetro, sem validar se o destino é confiável.",
                                "Location: " + location.get().value(),
                                "Valide o destino do redirecionamento contra uma allowlist de domínios/paths internos, ou use redirecionamentos relativos."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de Open Redirect (param " + param + "): " + e.getMessage());
            }
        }
        return achados;
    }
}
