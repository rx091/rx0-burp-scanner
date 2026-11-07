package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.FalsePositiveGuard;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tries to access a list of commonly sensitive paths (config files, backups,
 * .git, admin panels, etc) and reports the ones that respond with 200/access.
 * Created by Rx0 - @rodrigocoutinho91
 */
public class SensitivePathsCheck implements VulnCheck {

    private static final Map<String, Severity> PATHS = new LinkedHashMap<>();
    static {
        PATHS.put("/.git/config", Severity.CRITICAL);
        PATHS.put("/.git/HEAD", Severity.CRITICAL);
        PATHS.put("/.env", Severity.CRITICAL);
        PATHS.put("/.env.bak", Severity.CRITICAL);
        PATHS.put("/wp-config.php.bak", Severity.CRITICAL);
        PATHS.put("/config.php.bak", Severity.HIGH);
        PATHS.put("/backup.zip", Severity.HIGH);
        PATHS.put("/backup.sql", Severity.CRITICAL);
        PATHS.put("/dump.sql", Severity.CRITICAL);
        PATHS.put("/.DS_Store", Severity.LOW);
        PATHS.put("/phpinfo.php", Severity.HIGH);
        PATHS.put("/info.php", Severity.HIGH);
        PATHS.put("/server-status", Severity.MEDIUM);
        PATHS.put("/.well-known/security.txt", Severity.INFO);
        PATHS.put("/swagger.json", Severity.MEDIUM);
        PATHS.put("/swagger-ui.html", Severity.MEDIUM);
        PATHS.put("/openapi.json", Severity.MEDIUM);
        PATHS.put("/actuator/env", Severity.CRITICAL);
        PATHS.put("/actuator/health", Severity.LOW);
        PATHS.put("/.htaccess", Severity.MEDIUM);
        PATHS.put("/admin/", Severity.INFO);
        PATHS.put("/phpmyadmin/", Severity.MEDIUM);
        PATHS.put("/robots.txt", Severity.INFO);
        PATHS.put("/sitemap.xml", Severity.INFO);
    }

    @Override
    public String name() {
        return "Exposed sensitive paths and files";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, FalsePositiveGuard.calculate(api, baseUrl));
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, FalsePositiveGuard guard) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        if (guard.isLikelyCatchAll()) {
            api.logging().logToOutput("[Rx0] SensitivePathsCheck: catch-all/SPA detected — automatically filtering false positives.");
        }

        for (Map.Entry<String, Severity> entry : PATHS.entrySet()) {
            String path = entry.getKey();
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(base + path);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                int status = resp.statusCode();
                String body = resp.bodyToString();
                boolean empty = body == null || body.isBlank();

                // Automatically discard if the response matches the baseline's catch-all pattern
                if (guard.looksLikeFalsePositive(status, body)) continue;

                // Avoids the classic false positive from SPA apps that respond 200 with the same home page for everything
                boolean looksLikeRealContent = !empty && body.length() > 10;

                if (status == 200 && looksLikeRealContent) {
                    findings.add(new Finding(
                            "Potentially sensitive path reachable: " + path,
                            entry.getValue(),
                            base + path,
                            "The URL responded HTTP 200. Manually confirm whether the returned content is really the expected file/panel (this can be a false positive on SPAs with a route fallback).",
                            "Status: " + status + " | Body size: " + body.length() + " bytes",
                            "If the file/panel should not be public, remove it or restrict access by IP/authentication."));
                } else if (status == 403) {
                    findings.add(new Finding(
                            "Sensitive path exists but is blocked (403): " + path,
                            Severity.INFO,
                            base + path,
                            "The resource exists on the server (it returned 403 instead of 404), which confirms its presence even though access is denied.",
                            "Status: " + status,
                            "Keep the block in place and consider removing the file from the public directory when possible."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error checking path " + path + ": " + e.getMessage());
            }
        }
        return findings;
    }
}
