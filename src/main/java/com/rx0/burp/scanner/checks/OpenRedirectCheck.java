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
 * Tests common redirect parameters with a forged external URL and checks
 * whether the server redirects (3xx + Location) to it.
 * Created by Rx0 - @rodrigocoutinho91
 */
public class OpenRedirectCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"redirect", "redirect_uri", "url", "next", "return", "returnUrl", "continue", "dest"};
    private static final String EXTERNAL_DOMAIN = "rx0-redirect-test.evil.example";

    @Override
    public String name() {
        return "Open Redirect";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            try {
                String payload = "https://" + EXTERNAL_DOMAIN;
                String testUrl = base + "/?" + param + "=" + java.net.URLEncoder.encode(payload, "UTF-8");
                HttpRequest req = HttpRequest.httpRequestFromUrl(testUrl);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                int status = resp.statusCode();
                if (status >= 300 && status < 400) {
                    Optional<HttpHeader> location = resp.headers().stream()
                            .filter(h -> h.name().equalsIgnoreCase("Location"))
                            .findFirst();
                    if (location.isPresent() && location.get().value().contains(EXTERNAL_DOMAIN)) {
                        findings.add(new Finding(
                                "Possible Open Redirect in parameter '" + param + "'",
                                Severity.MEDIUM,
                                testUrl,
                                "The application redirected (HTTP " + status + ") to an attacker-controlled external domain taken from the parameter value, without validating whether the destination is trusted.",
                                "Location: " + location.get().value(),
                                "Validate the redirect destination against an allowlist of trusted internal domains/paths, or use relative redirects."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in Open Redirect check (param " + param + "): " + e.getMessage());
            }
        }
        return findings;
    }
}
