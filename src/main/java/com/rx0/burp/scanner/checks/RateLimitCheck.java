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
 * Fires a burst of requests at common login/API endpoints and checks whether
 * the server applies any form of rate limiting (HTTP 429, or progressive
 * blocking). Its absence makes credential brute-forcing and API abuse easier
 * (API4:2023 Unrestricted Resource Consumption).
 *
 * The volume is deliberately low (12 requests) to avoid generating excessive
 * load — adjust BURST_SIZE for a more aggressive test.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class RateLimitCheck implements VulnCheck {

    private static final String[] PATHS = {"/api/login", "/api/v1/login", "/api/auth/login", "/login"};
    private static final int BURST_SIZE = 12;

    @Override
    public String name() {
        return "Rate limiting on login/API endpoints";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                String body = "{\"username\":\"rx0_test_user\",\"password\":\"invalid_password_" + System.currentTimeMillis() + "\"}";

                int unblockedSuccesses = 0;
                boolean gotAnyResponse = false;

                for (int i = 0; i < BURST_SIZE; i++) {
                    HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                            .withMethod("POST")
                            .withAddedHeader("Content-Type", "application/json")
                            .withBody(body);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;
                    gotAnyResponse = true;

                    int status = resp.statusCode();
                    if (status == 429 || status == 403) {
                        unblockedSuccesses = -1; // found a block, stop the burst
                        break;
                    }
                    // treats any normal response (200/400/401) that isn't a rate-limit as "unblocked"
                    unblockedSuccesses++;
                }

                if (gotAnyResponse && unblockedSuccesses >= BURST_SIZE) {
                    findings.add(new Finding(
                            "Possible absence of rate limiting at " + path,
                            Severity.MEDIUM,
                            url,
                            BURST_SIZE + " consecutive login attempts were sent without the server ever returning " +
                                    "HTTP 429 (Too Many Requests) or 403. This can make brute-force attacks and " +
                                    "credential stuffing easier.",
                            BURST_SIZE + " requests sent, none blocked.",
                            "Implement rate limiting (per IP and/or per account) and consider CAPTCHA or progressive lockout after failed attempts."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in rate limit check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }
}
