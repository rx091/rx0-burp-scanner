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
 * Injects unique markers into QUERY parameters and also into the BODY (JSON
 * and form-urlencoded) of POST requests, testing several payload contexts
 * (raw HTML tag, attribute breakout, script breakout), and checks whether the
 * payload comes back WITHOUT escaping in the response — indicating possible
 * reflected XSS.
 *
 * Just a non-intrusive probe (does not actually execute the JS) — it does not
 * confirm real exploitation, but it is a strong signal of missing output encoding.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class ReflectedXssCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {
            "q", "search", "s", "query", "name", "id", "redirect", "url",
            "comment", "message", "title", "description", "tag", "keyword"
    };

    private static final String MARKER = "rx0" + (System.currentTimeMillis() % 100000);

    // Payloads in different contexts: raw tag, attribute breakout, script breakout
    private static final String[] PAYLOADS = {
            "<rx0xss>" + MARKER + "</rx0xss>",
            "\"><rx0xss " + MARKER + "=1>",
            "'><rx0xss " + MARKER + "=1>",
            "</script><rx0xss>" + MARKER + "</rx0xss><script>",
            "<img src=x onerror=rx0_" + MARKER + "()>",
            "<svg onload=rx0_" + MARKER + "()>",
    };

    @Override
    public String name() {
        return "Reflected XSS (GET + POST, multiple contexts)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        findings.addAll(testViaQueryString(api, base));
        findings.addAll(testViaJsonBody(api, base));
        findings.addAll(testViaFormUrlEncodedBody(api, base));

        return findings;
    }

    private List<Finding> testViaQueryString(MontoyaApi api, String base) {
        List<Finding> findings = new ArrayList<>();
        for (String param : PARAM_NAMES) {
            for (String payload : PAYLOADS) {
                try {
                    String testUrl = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                    HttpRequest req = HttpRequest.httpRequestFromUrl(testUrl);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body != null && body.contains(payload)) {
                        findings.add(buildFinding(param, testUrl, payload, "query string (GET)"));
                        break; // already confirmed on this param, skip the other payloads
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error in GET XSS (param " + param + "): " + e.getMessage());
                }
            }
        }
        return findings;
    }

    private List<Finding> testViaJsonBody(MontoyaApi api, String base) {
        List<Finding> findings = new ArrayList<>();
        String[] paths = {"/api/comments", "/api/search", "/api/feedback", "/api/contact"};
        for (String path : paths) {
            for (String param : new String[]{"comment", "message", "name", "search", "content"}) {
                try {
                    String payload = PAYLOADS[0];
                    String requestBody = "{\"" + param + "\":\"" + payload.replace("\"", "\\\"") + "\"}";
                    HttpRequest req = HttpRequest.httpRequestFromUrl(base + path)
                            .withMethod("POST")
                            .withAddedHeader("Content-Type", "application/json")
                            .withBody(requestBody);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String responseBody = resp.bodyToString();
                    if (responseBody != null && responseBody.contains(payload)) {
                        findings.add(buildFinding(param, base + path, payload, "JSON body (POST)"));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error in JSON XSS (" + path + "/" + param + "): " + e.getMessage());
                }
            }
        }
        return findings;
    }

    private List<Finding> testViaFormUrlEncodedBody(MontoyaApi api, String base) {
        List<Finding> findings = new ArrayList<>();
        String[] paths = {"/search", "/comment", "/contact", "/feedback"};
        for (String path : paths) {
            for (String param : new String[]{"q", "comment", "message", "name"}) {
                try {
                    String payload = PAYLOADS[0];
                    String requestBody = param + "=" + URLEncoder.encode(payload, "UTF-8");
                    HttpRequest req = HttpRequest.httpRequestFromUrl(base + path)
                            .withMethod("POST")
                            .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                            .withBody(requestBody);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String responseBody = resp.bodyToString();
                    if (responseBody != null && responseBody.contains(payload)) {
                        findings.add(buildFinding(param, base + path, payload, "form-urlencoded body (POST)"));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error in form XSS (" + path + "/" + param + "): " + e.getMessage());
                }
            }
        }
        return findings;
    }

    private Finding buildFinding(String param, String url, String payload, String source) {
        return new Finding(
                "Possible reflected XSS in parameter '" + param + "' via " + source,
                Severity.HIGH,
                url,
                "The test payload was reflected in the response without escaping, indicating a lack of output " +
                        "sanitization/encoding at this point in the application (source: " + source + ").",
                "Payload: " + payload + " | Found verbatim in the response.",
                "Apply output encoding (HTML entity encoding) to any data reflected in HTML, validate the response's " +
                        "Content-Type, and implement CSP as defense in depth.",
                "1) Open the URL in a browser: " + url + " 2) If the test payload (<rx0xss>) did not execute because it is a " +
                        "harmless tag, swap it for a real PoC payload, e.g.: <script>alert(document.cookie)</script> or " +
                        "<img src=x onerror=alert(document.domain)> in the same parameter '" + param + "'. 3) Confirm the " +
                        "JavaScript executed (the alert popup) in the browser. 4) For real impact, demonstrate cookie/session " +
                        "theft by sending document.cookie to a controlled listener (e.g. webhook.site) — always documenting it as a PoC, never against production without specific authorization for it.");
    }
}
