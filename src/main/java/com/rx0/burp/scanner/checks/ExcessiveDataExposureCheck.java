package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans responses from common API endpoints for JSON FIELDS suggesting
 * excessive exposure of sensitive data (API3:2023 Broken Object Property
 * Level Authorization / Excessive Data Exposure): plaintext password, hash,
 * tokens, secrets, API keys, national ID numbers, credit card.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class ExcessiveDataExposureCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/users", "/api/v1/users", "/api/user/me", "/api/me", "/api/profile",
            "/api/accounts", "/api/customers"
    };

    private static final Pattern[] SENSITIVE_FIELDS = {
            Pattern.compile("\"password\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"senha\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"password_hash\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(api_key|apikey|api_secret)\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"secret\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(access_token|refresh_token)\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(cpf|cnpj)\"\\s*:\\s*\"?\\d", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(credit_card|card_number|cc_number)\"\\s*:\\s*\"?\\d", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"ssn\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String name() {
        return "Excessive data exposure in API responses";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url).withAddedHeader("Accept", "application/json");
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null || resp.statusCode() != 200) continue;

                String body = resp.bodyToString();
                if (body == null || body.isBlank()) continue;

                for (Pattern p : SENSITIVE_FIELDS) {
                    Matcher m = p.matcher(body);
                    if (m.find()) {
                        findings.add(new Finding(
                                "Possible excessive data exposure at " + path,
                                Severity.HIGH,
                                url,
                                "The API response contains a field that looks like sensitive data returned unnecessarily " +
                                        "(password, token, secret, or a personal document number). This is a classic Excessive Data Exposure " +
                                        "pattern (OWASP API Security Top 10 API3:2023).",
                                "Matching snippet: " + summarize(m.group(), 120),
                                "Filter the API response to return only the fields the client actually needs (use explicit DTOs/serializers, never serialize the whole entity)."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in data exposure check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }

    private String summarize(String text, int max) {
        if (text.length() <= max) return text;
        return text.substring(0, max) + "...";
    }
}
