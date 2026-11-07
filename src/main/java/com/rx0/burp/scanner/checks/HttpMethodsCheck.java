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
 * Checks for dangerous HTTP methods enabled on the server:
 *  - TRACE enabled (Cross-Site Tracing / XST)
 *  - Allow header (via OPTIONS) exposing PUT/DELETE with no apparent authentication
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class HttpMethodsCheck implements VulnCheck {

    @Override
    public String name() {
        return "Dangerous HTTP methods (TRACE/PUT/DELETE)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();

        // 1) OPTIONS — see what the server says is allowed
        try {
            HttpRequest optionsReq = HttpRequest.httpRequestFromUrl(baseUrl).withMethod("OPTIONS");
            HttpResponse optionsResp = api.http().sendRequest(optionsReq).response();
            if (optionsResp != null) {
                Optional<HttpHeader> allow = optionsResp.headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Allow") || h.name().equalsIgnoreCase("Access-Control-Allow-Methods"))
                        .findFirst();
                if (allow.isPresent()) {
                    String value = allow.get().value().toUpperCase();
                    if (value.contains("PUT") || value.contains("DELETE") || value.contains("PATCH")) {
                        findings.add(new Finding(
                                "Write methods exposed via " + allow.get().name(),
                                Severity.LOW,
                                baseUrl,
                                "The server advertises support for write/modification methods (PUT/DELETE/PATCH) on this root route. " +
                                        "This isn't necessarily a flaw, but it's worth confirming these methods require proper " +
                                        "authentication when used on real API endpoints.",
                                allow.get().name() + ": " + allow.get().value(),
                                "Make sure every write method requires authentication and authorization, and disable unused methods."));
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error checking OPTIONS: " + e.getMessage());
        }

        // 2) TRACE — Cross-Site Tracing (XST)
        try {
            String marker = "Rx0-XST-Test: " + System.currentTimeMillis();
            HttpRequest traceReq = HttpRequest.httpRequestFromUrl(baseUrl)
                    .withMethod("TRACE")
                    .withAddedHeader("X-Rx0-Marker", marker);
            HttpResponse traceResp = api.http().sendRequest(traceReq).response();
            if (traceResp != null && traceResp.statusCode() == 200) {
                String body = traceResp.bodyToString();
                if (body != null && body.contains("X-Rx0-Marker")) {
                    findings.add(new Finding(
                            "TRACE method enabled (Cross-Site Tracing)",
                            Severity.MEDIUM,
                            baseUrl,
                            "The server accepts TRACE requests and reflects the sent headers back in the response body. " +
                                    "Combined with XSS, this can be used to steal HttpOnly cookies via Cross-Site Tracing (XST).",
                            "Marker header reflected in the TRACE response.",
                            "Disable the TRACE (and TRACK) method on the web server."));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error checking TRACE: " + e.getMessage());
        }

        return findings;
    }
}
