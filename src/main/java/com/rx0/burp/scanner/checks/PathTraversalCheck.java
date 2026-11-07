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
 * Tests parameters that typically serve files (file, path, page, template,
 * document...) with classic Path Traversal / Local File Inclusion payloads,
 * looking for the signature of /etc/passwd (Linux) or win.ini (Windows)
 * reflected in the response.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class PathTraversalCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {
            "file", "path", "page", "document", "doc", "template", "filename",
            "include", "load", "view", "folder", "dir", "download"
    };

    private static final String[] PAYLOADS = {
            "../../../../../../etc/passwd",
            "....//....//....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "/etc/passwd",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    };

    private static final Pattern PASSWD_SIGNATURE = Pattern.compile("root:.*:0:0:", Pattern.CASE_INSENSITIVE);
    private static final Pattern WININI_SIGNATURE = Pattern.compile("\\[extensions\\]|\\[fonts\\]", Pattern.CASE_INSENSITIVE);

    @Override
    public String name() {
        return "Path Traversal / Local File Inclusion";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            for (String payload : PAYLOADS) {
                try {
                    String url = base + "/?" + param + "=" + payload; // not fully URL-encoded: some servers only normalize the decoded form
                    HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body == null) continue;

                    boolean foundPasswd = PASSWD_SIGNATURE.matcher(body).find();
                    boolean foundWinIni = WININI_SIGNATURE.matcher(body).find();

                    if (foundPasswd || foundWinIni) {
                        findings.add(new Finding(
                                "Possible Path Traversal / LFI in parameter '" + param + "'",
                                Severity.CRITICAL,
                                url,
                                "Sending a directory traversal payload resulted in system file content " +
                                        "(" + (foundPasswd ? "/etc/passwd" : "win.ini") + ") reflected in the response — the parameter allows " +
                                        "arbitrary file reads on the server.",
                                "Payload: " + payload,
                                "Never build file paths from user input. Use a fixed ID-to-file map for the allowed files " +
                                        "(allowlist) and normalize/validate the resulting path before any filesystem access.",
                                "1) In Repeater, resend swapping the target for the application's config files (e.g. ../../../etc/app/config.yml, " +
                                        "web.xml, .env, wp-config.php — adjust the number of ../ to the server's actual depth). " +
                                        "2) If the application is PHP and you suspect real LFI (not just a read), try escalating to RCE via " +
                                        "log poisoning (reading the Apache/Nginx access.log after injecting PHP into the User-Agent) or via php://filter " +
                                        "to read source code in base64. 3) Document every sensitive file that is reachable."));
                        break; // already confirmed on this param, no need to test the other payloads
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error in Path Traversal check (param " + param + "): " + e.getMessage());
                }
            }
        }
        return findings;
    }
}
