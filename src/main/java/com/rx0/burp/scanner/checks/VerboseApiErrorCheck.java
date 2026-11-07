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
 * Sends malformed JSON / an unexpected data type to common API endpoints and
 * checks whether the error response exposes a stack trace, a server file
 * path, or a framework name — valuable information for an attacker mapping
 * the stack and looking for other flaws.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class VerboseApiErrorCheck implements VulnCheck {

    private static final String[] PATHS = {"/api/login", "/api/users", "/api/v1/users", "/api/search", "/api/orders"};
    private static final String MALFORMED_BODY = "{\"id\": {\"$ne\": null}, \"rx0\": }"; // deliberately broken JSON

    private static final Pattern[] SIGNATURES = {
            Pattern.compile("at [\\w.$]+\\([\\w.]+\\.java:\\d+\\)"), // Java stack trace
            Pattern.compile("Traceback \\(most recent call last\\)"), // Python
            Pattern.compile("Fatal error:.*on line \\d+", Pattern.CASE_INSENSITIVE), // PHP
            Pattern.compile("System\\.\\w+Exception"), // .NET
            Pattern.compile("at Object\\.<anonymous>"), // Node.js
            Pattern.compile("/(usr|var|home|opt)/[\\w./-]+"), // Unix file path in the body
            Pattern.compile("[A-Z]:\\\\\\\\[\\w\\\\.-]+"), // Windows file path
            Pattern.compile("\"stack\"\\s*:\\s*\"", Pattern.CASE_INSENSITIVE), // "stack" field in error JSON
    };

    @Override
    public String name() {
        return "Verbose errors / stack trace in API responses";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(MALFORMED_BODY);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                for (Pattern p : SIGNATURES) {
                    if (p.matcher(body).find()) {
                        findings.add(new Finding(
                                "Verbose error exposes internal details at " + path,
                                Severity.MEDIUM,
                                url,
                                "Sending a malformed JSON body caused an error response that exposes a stack trace, " +
                                        "a server file path, or an internal framework name. This helps an attacker map the " +
                                        "technology stack and locate other vulnerabilities.",
                                "Status: " + resp.statusCode() + " | Signature detected: " + p.pattern(),
                                "Catch exceptions on the backend and return generic error messages to the client; log the full detail server-side only."));
                        break; // one signature is enough for this path
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in verbose error check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }
}
