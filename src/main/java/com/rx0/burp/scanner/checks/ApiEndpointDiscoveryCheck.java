package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.FalsePositiveGuard;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Tries to access commonly sensitive API endpoints WITHOUT sending any
 * credentials, looking for responses that look like real data (JSON)
 * instead of 401/403 — a classic sign of Broken Authentication / BOLA
 * (OWASP API Security Top 10: API1 and API2).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class ApiEndpointDiscoveryCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/users", "/api/v1/users", "/api/v2/users",
            "/api/admin", "/api/v1/admin", "/api/internal",
            "/api/config", "/api/debug", "/api/health",
            "/api/accounts", "/api/customers", "/api/orders",
            "/api/v1/user/me", "/api/me", "/api/profile",
            "/api/v1/auth/users", "/api/private",
            "/.well-known/openid-configuration",
    };

    @Override
    public String name() {
        return "Unauthenticated API endpoint discovery";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, FalsePositiveGuard.calculate(api, baseUrl));
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, FalsePositiveGuard guard) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(base + path)
                        .withAddedHeader("Accept", "application/json");
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                int status = resp.statusCode();
                if (status != 200) continue;

                String body = resp.bodyToString();
                if (guard.looksLikeFalsePositive(status, body)) continue;

                Optional<HttpHeader> contentType = resp.headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                        .findFirst();
                boolean looksLikeJson = contentType.isPresent() && contentType.get().value().toLowerCase().contains("json");

                boolean hasContent = body != null && body.trim().length() > 2
                        && (body.trim().startsWith("{") || body.trim().startsWith("["));

                if (looksLikeJson || hasContent) {
                    findings.add(new Finding(
                            "API endpoint reachable without authentication: " + path,
                            Severity.HIGH,
                            base + path,
                            "The request with no credentials returned HTTP 200 with content that looks like real-data JSON. " +
                                    "This may indicate an authentication failure (API1:2023 Broken Object Level Authorization / API2:2023 Broken Authentication). " +
                                    "Manually verify whether sensitive data is actually being exposed.",
                            "Status: 200 | Content-Type: " + contentType.map(HttpHeader::value).orElse("unknown")
                                    + " | Body size: " + (body != null ? body.length() : 0) + " bytes",
                            "Require authentication and authorization (ownership verification) on every API endpoint that returns user/business data."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error checking API endpoint " + path + ": " + e.getMessage());
            }
        }
        return findings;
    }
}
