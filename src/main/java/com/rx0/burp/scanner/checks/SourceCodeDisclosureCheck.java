package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.FalsePositiveGuard;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Tests backup/editor filename variations on top of common base names
 * (index, config, login, database, admin) with extensions that make the
 * server serve the SOURCE CODE instead of executing it (.bak, ~, .swp,
 * .orig, .old) — a classic sign of a misconfigured server after a deploy
 * or direct in-place editing on the server.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class SourceCodeDisclosureCheck implements VulnCheck {

    private static final String[] BASE_NAMES = {"index", "config", "login", "database", "db", "admin", "connect", "settings"};
    private static final String[] BASE_EXTENSIONS = {".php", ".asp", ".aspx", ".jsp", ".java"};
    private static final String[] BACKUP_SUFFIXES = {".bak", "~", ".swp", ".orig", ".old", ".save", ".1"};

    private static final Pattern[] CODE_SIGNATURES = {
            Pattern.compile("<\\?php"),
            Pattern.compile("import\\s+java\\.|package\\s+[\\w.]+;"),
            Pattern.compile("using\\s+System;|namespace\\s+\\w+"),
            Pattern.compile("<%@\\s*page"), // JSP
            Pattern.compile("require\\(|include\\(|function\\s+\\w+\\s*\\("),
            Pattern.compile("SELECT\\s+.+\\s+FROM\\s+", Pattern.CASE_INSENSITIVE), // SQL embedded in a config file
    };

    @Override
    public String name() {
        return "Exposed source code / backup file";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, FalsePositiveGuard.calculate(api, baseUrl));
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, FalsePositiveGuard guard) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String baseName : BASE_NAMES) {
            for (String extension : BASE_EXTENSIONS) {
                for (String suffix : BACKUP_SUFFIXES) {
                    try {
                        String path = "/" + baseName + extension + suffix;
                        String url = base + path;
                        HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
                        if (resp == null || resp.statusCode() != 200) continue;

                        String body = resp.bodyToString();
                        if (body == null || body.isBlank()) continue;
                        if (guard.looksLikeFalsePositive(resp.statusCode(), body)) continue;

                        for (Pattern p : CODE_SIGNATURES) {
                            if (p.matcher(body).find()) {
                                findings.add(new Finding(
                                        "Exposed source code: " + path,
                                        Severity.CRITICAL,
                                        url,
                                        "A backup/editor file was found publicly accessible and contains server-side " +
                                                "source code (instead of being executed, it was served as plain text) — this can " +
                                                "expose business logic, hardcoded credentials, and implementation details.",
                                        "Code signature found: " + p.pattern() + " | Body size: " + body.length() + " bytes",
                                        "Remove backup/temporary files from the web server's public directory, and configure the editor " +
                                                "(e.g. vim) to avoid leaving .swp files in the production project folder."));
                                break;
                            }
                        }
                    } catch (Exception e) {
                        api.logging().logToError("[Rx0] Error in source code disclosure check: " + e.getMessage());
                    }
                }
            }
        }
        return findings;
    }
}
