package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Identifies the target's technology/CMS/framework via signatures in
 * headers, cookies, and markers in the HTML. This isn't a flaw by itself —
 * it's an INFORMATIONAL finding that helps direct the rest of the manual
 * testing (e.g. if it's WordPress, run wpscan; if it's Laravel, check for
 * exposed debug mode).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class TechFingerprintCheck implements VulnCheck {

    private static final Map<String, Pattern> HTML_SIGNATURES = new LinkedHashMap<>();
    static {
        HTML_SIGNATURES.put("WordPress", Pattern.compile("wp-content|wp-includes|/wp-json/", Pattern.CASE_INSENSITIVE));
        HTML_SIGNATURES.put("Joomla", Pattern.compile("Joomla!|/media/jui/", Pattern.CASE_INSENSITIVE));
        HTML_SIGNATURES.put("Drupal", Pattern.compile("Drupal\\.settings|/sites/default/files", Pattern.CASE_INSENSITIVE));
        HTML_SIGNATURES.put("Laravel", Pattern.compile("laravel_session|XSRF-TOKEN", Pattern.CASE_INSENSITIVE));
        HTML_SIGNATURES.put("Django", Pattern.compile("csrfmiddlewaretoken", Pattern.CASE_INSENSITIVE));
        HTML_SIGNATURES.put("Ruby on Rails", Pattern.compile("authenticity_token|data-turbo", Pattern.CASE_INSENSITIVE));
        HTML_SIGNATURES.put("ASP.NET", Pattern.compile("__VIEWSTATE|__EVENTVALIDATION", Pattern.CASE_INSENSITIVE));
        HTML_SIGNATURES.put("React", Pattern.compile("__NEXT_DATA__|data-reactroot|react-dom", Pattern.CASE_INSENSITIVE));
        HTML_SIGNATURES.put("Angular", Pattern.compile("ng-version|ng-app", Pattern.CASE_INSENSITIVE));
        HTML_SIGNATURES.put("Vue.js", Pattern.compile("data-v-[a-f0-9]{6,}|__VUE__", Pattern.CASE_INSENSITIVE));
    }

    private static final Map<String, Pattern> COOKIE_SIGNATURES = new LinkedHashMap<>();
    static {
        COOKIE_SIGNATURES.put("PHP", Pattern.compile("PHPSESSID", Pattern.CASE_INSENSITIVE));
        COOKIE_SIGNATURES.put("Java (JSESSIONID)", Pattern.compile("JSESSIONID", Pattern.CASE_INSENSITIVE));
        COOKIE_SIGNATURES.put("ASP.NET", Pattern.compile("ASP\\.NET_SessionId", Pattern.CASE_INSENSITIVE));
        COOKIE_SIGNATURES.put("Express/Node.js", Pattern.compile("connect\\.sid", Pattern.CASE_INSENSITIVE));
    }

    @Override
    public String name() {
        return "Technology fingerprint (CMS/framework)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(baseUrl)).response();
            if (resp == null) return findings;

            List<String> detected = new ArrayList<>();
            String body = resp.bodyToString();
            if (body != null) {
                for (Map.Entry<String, Pattern> entry : HTML_SIGNATURES.entrySet()) {
                    if (entry.getValue().matcher(body).find()) detected.add(entry.getKey());
                }
            }

            StringBuilder cookiesSeen = new StringBuilder();
            for (HttpHeader h : resp.headers()) {
                if (!h.name().equalsIgnoreCase("Set-Cookie")) continue;
                cookiesSeen.append(h.value()).append(" ");
            }
            for (Map.Entry<String, Pattern> entry : COOKIE_SIGNATURES.entrySet()) {
                if (entry.getValue().matcher(cookiesSeen).find()) detected.add(entry.getKey());
            }

            // Server/X-Powered-By are already reported by SecurityHeadersCheck, but here we roll them into the fingerprint
            String server = null, poweredBy = null;
            for (HttpHeader h : resp.headers()) {
                if (h.name().equalsIgnoreCase("Server")) server = h.value();
                if (h.name().equalsIgnoreCase("X-Powered-By")) poweredBy = h.value();
            }

            if (!detected.isEmpty() || server != null || poweredBy != null) {
                StringBuilder summary = new StringBuilder();
                if (!detected.isEmpty()) summary.append("Technologies detected: ").append(String.join(", ", detected)).append(". ");
                if (server != null) summary.append("Server: ").append(server).append(". ");
                if (poweredBy != null) summary.append("X-Powered-By: ").append(poweredBy).append(".");

                findings.add(new Finding(
                        "Target technology fingerprint",
                        Severity.INFO,
                        baseUrl,
                        "Identification of the target's technology stack, useful for guiding complementary manual testing " +
                                "(e.g. WordPress → run wpscan; Laravel → check for exposed debug mode/.env; ASP.NET → review the ViewState).",
                        summary.toString().trim(),
                        "Consider hiding version headers (Server, X-Powered-By) to make automated reconnaissance harder, " +
                                "though this is only 'security through obscurity' — keep the software up to date at all times."));
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error in fingerprint check: " + e.getMessage());
        }
        return findings;
    }
}
