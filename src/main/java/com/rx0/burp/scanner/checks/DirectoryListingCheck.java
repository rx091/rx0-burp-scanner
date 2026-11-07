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
 * Tests common directories looking for enabled Directory Listing
 * (the server lists the folder's contents instead of serving an index/404).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class DirectoryListingCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/images/", "/img/", "/uploads/", "/upload/", "/files/", "/file/",
            "/backup/", "/backups/", "/assets/", "/static/", "/media/", "/tmp/", "/logs/"
    };

    private static final Pattern[] SIGNATURES = {
            Pattern.compile("Index of /", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<title>Directory listing for", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\[To Parent Directory\\]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<h1>Index of", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String name() {
        return "Directory Listing enabled";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, FalsePositiveGuard.calculate(api, baseUrl));
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, FalsePositiveGuard guard) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;
                if (guard.looksLikeFalsePositive(resp.statusCode(), body)) continue;

                for (Pattern p : SIGNATURES) {
                    if (p.matcher(body).find()) {
                        findings.add(new Finding(
                                "Directory Listing enabled at " + path,
                                Severity.INFO,
                                url,
                                "The server lists the directory's contents instead of returning an index/404, exposing the " +
                                        "file structure and potentially files not intended for public access.",
                                "Signature found: " + p.pattern(),
                                "Disable directory listing on the web server (e.g. 'Options -Indexes' on Apache, " +
                                        "'autoindex off;' on Nginx) and place an empty index file in public folders if needed."));
                        break;
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in Directory Listing check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }
}
