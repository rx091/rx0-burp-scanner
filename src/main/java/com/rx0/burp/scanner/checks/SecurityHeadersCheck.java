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
 * Checks for the absence of important security headers in the HTTP response.
 * Created by Rx0 - @rodrigocoutinho91
 */
public class SecurityHeadersCheck implements VulnCheck {

    @Override
    public String name() {
        return "Security headers";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return findings;

            checkMissing(findings, resp, baseUrl, "Content-Security-Policy", Severity.MEDIUM,
                    "Missing Content-Security-Policy (CSP)",
                    "Without CSP the browser does not restrict the origin of scripts/styles, making XSS and content injection easier.",
                    "Define a restrictive CSP policy (default-src 'self' with the minimum necessary exceptions).");

            checkMissing(findings, resp, baseUrl, "X-Frame-Options", Severity.MEDIUM,
                    "Missing X-Frame-Options",
                    "The site can be loaded inside a third-party <iframe>, opening the door to clickjacking.",
                    "Add X-Frame-Options: DENY or SAMEORIGIN (or frame-ancestors via CSP).");

            checkMissing(findings, resp, baseUrl, "Strict-Transport-Security", Severity.MEDIUM,
                    "Missing HSTS (Strict-Transport-Security)",
                    "Without HSTS, connections can be forced down to HTTP, opening the door to downgrade/MITM attacks.",
                    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.");

            checkMissing(findings, resp, baseUrl, "X-Content-Type-Options", Severity.LOW,
                    "Missing X-Content-Type-Options",
                    "Without this header, older browsers may try to 'guess' the content type (MIME sniffing).",
                    "Add X-Content-Type-Options: nosniff.");

            checkMissing(findings, resp, baseUrl, "Referrer-Policy", Severity.LOW,
                    "Missing Referrer-Policy",
                    "Without this policy, the full URL can leak to third parties via the Referer header.",
                    "Add Referrer-Policy: strict-origin-when-cross-origin (or something more restrictive).");

            checkMissing(findings, resp, baseUrl, "Permissions-Policy", Severity.INFO,
                    "Missing Permissions-Policy",
                    "Without this policy, the browser does not restrict the use of sensitive APIs (camera, geolocation, etc).",
                    "Define a Permissions-Policy limiting features to those actually needed.");

            // Technology banners that make fingerprinting easier
            for (HttpHeader h : resp.headers()) {
                String name = h.name();
                if (name.equalsIgnoreCase("Server") || name.equalsIgnoreCase("X-Powered-By")) {
                    findings.add(new Finding(
                            "Technology disclosure via " + name + " header",
                            Severity.INFO,
                            baseUrl,
                            "The '" + name + "' header exposes information about the server stack: " + h.value(),
                            name + ": " + h.value(),
                            "Remove or mask this header on the web server / reverse proxy."
                    ));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error in headers check: " + e.getMessage());
        }
        return findings;
    }

    private void checkMissing(List<Finding> findings, HttpResponse resp, String url, String headerName,
                               Severity sev, String title, String description, String recommendation) {
        boolean present = resp.headers().stream().anyMatch(h -> h.name().equalsIgnoreCase(headerName));
        if (!present) {
            findings.add(new Finding(title, sev, url, description, "Header '" + headerName + "' not found in the response.", recommendation));
        }
    }
}
