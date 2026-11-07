package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans the body of the home page (and a few common paths) for sensitive
 * data leaking directly in the served HTML/JS/JSON: a private key, mass
 * emails, private IP addresses, credit card numbers and national ID / SSN
 * numbers in plain text.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class SensitiveDataInBodyCheck implements VulnCheck {

    private static final String[] PATHS = {"/", "/sitemap.xml", "/about", "/contact", "/humans.txt"};

    private static final Map<String, Pattern> SIGNATURES = new LinkedHashMap<>();
    static {
        SIGNATURES.put("Exposed private key",
                Pattern.compile("-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"));
        SIGNATURES.put("Exposed private JSON Web Key (JWK)",
                Pattern.compile("\"kty\"\\s*:\\s*\"(RSA|EC)\".{0,400}\"d\"\\s*:\\s*\"", Pattern.DOTALL));
        SIGNATURES.put("Exposed private IP address",
                Pattern.compile("\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b"));
        SIGNATURES.put("Possible exposed credit card number",
                Pattern.compile("\\b(?:\\d[ -]*?){13,16}\\b"));
        SIGNATURES.put("Possible exposed national ID / SSN",
                Pattern.compile("\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b|\\b\\d{3}-\\d{2}-\\d{4}\\b"));
        SIGNATURES.put("Exposed database connection string",
                Pattern.compile("(jdbc:|mongodb(\\+srv)?://|Server=.+;Database=|Data Source=.+;)", Pattern.CASE_INSENSITIVE));
    }

    // Threshold of distinct emails to consider a "mass leak" (avoids flagging 1 legitimate contact email)
    private static final int EMAIL_THRESHOLD = 5;
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[\\w.+-]+@[\\w-]+\\.[\\w.-]+");

    @Override
    public String name() {
        return "Sensitive data leaking in the response body";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
                if (resp == null || resp.statusCode() != 200) continue;

                String body = resp.bodyToString();
                if (body == null || body.isBlank()) continue;

                for (Map.Entry<String, Pattern> entry : SIGNATURES.entrySet()) {
                    Matcher m = entry.getValue().matcher(body);
                    if (m.find()) {
                        boolean sensitive = entry.getKey().contains("private key") || entry.getKey().contains("JWK")
                                || entry.getKey().contains("connection string");
                        findings.add(new Finding(
                                entry.getKey() + " at " + path,
                                sensitive ? Severity.CRITICAL : Severity.MEDIUM,
                                url,
                                "A pattern matching '" + entry.getKey().toLowerCase() + "' was found directly in the response body. " +
                                        "Manually confirm it's genuine (some patterns like credit card/national ID can have false positives — " +
                                        "numbers that match the format but aren't real data).",
                                "Matching snippet: " + summarize(mask(m.group()), 100),
                                sensitive
                                        ? "Immediately remove this data from the code/public response and rotate the credential/key if it's real."
                                        : "Avoid exposing this type of data in public responses; if it's intentional (e.g. a contact page), disregard this finding."));
                    }
                }

                // Mass emails (separate, since it counts occurrences rather than a simple find())
                Matcher emailMatcher = EMAIL_PATTERN.matcher(body);
                int emailCount = 0;
                while (emailMatcher.find()) emailCount++;
                if (emailCount >= EMAIL_THRESHOLD) {
                    findings.add(new Finding(
                            "Possible mass email leak at " + path,
                            Severity.MEDIUM,
                            url,
                            emailCount + " distinct email addresses were found in the response body. " +
                                    "This could be a user/contact list improperly exposed (as opposed to 1-2 legitimate contact " +
                                    "emails on an institutional page).",
                            "Number of emails found: " + emailCount,
                            "Review whether this many emails should be public; if it's a user listing, restrict access to it."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in sensitive data in body check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }

    private String mask(String text) {
        if (text.length() <= 8) return text;
        return text.substring(0, 4) + "****" + text.substring(text.length() - 4);
    }

    private String summarize(String text, int max) {
        if (text.length() <= max) return text;
        return text.substring(0, max) + "...";
    }
}
