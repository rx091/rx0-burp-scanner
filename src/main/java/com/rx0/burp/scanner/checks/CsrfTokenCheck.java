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
 * STATIC analysis: looks for <form method="post"> elements on the home page
 * (and common login/signup paths) and checks whether there is any hidden
 * field whose name suggests an anti-CSRF token (csrf, token, authenticity,
 * nonce...). POST forms with no such field are a sign of missing CSRF
 * protection — requires manual confirmation (some frameworks use SameSite
 * cookies or a custom header instead of a hidden field).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class CsrfTokenCheck implements VulnCheck {

    private static final String[] PATHS = {"/", "/login", "/signup", "/register", "/contact", "/comment"};

    private static final Pattern POST_FORM_PATTERN = Pattern.compile(
            "<form\\b[^>]*method=[\"']?post[\"']?[^>]*>(.*?)</form>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private static final Pattern TOKEN_FIELD_PATTERN = Pattern.compile(
            "<input[^>]*name=[\"']?(csrf|_csrf|csrf_token|authenticity_token|_token|nonce|xsrf|anti[-_]?forgery)[^\"'>]*[\"']?",
            Pattern.CASE_INSENSITIVE);

    @Override
    public String name() {
        return "CSRF — forms with no anti-CSRF token";
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
                if (body == null) continue;

                Matcher formMatcher = POST_FORM_PATTERN.matcher(body);
                int formIndex = 0;
                while (formMatcher.find()) {
                    formIndex++;
                    String formContent = formMatcher.group(1);
                    boolean hasToken = TOKEN_FIELD_PATTERN.matcher(formContent).find();

                    if (!hasToken) {
                        findings.add(new Finding(
                                "POST form with no apparent anti-CSRF token (form #" + formIndex + ") at " + path,
                                Severity.MEDIUM,
                                url,
                                "A form with method=\"post\" was found with no hidden field named like a typical " +
                                        "anti-CSRF token (csrf, _token, authenticity_token...). This MAY be a CSRF flaw — but " +
                                        "it could also be protected via a SameSite cookie, a custom header (e.g. X-CSRF-Token via JS) " +
                                        "or the Double Submit Cookie pattern, none of which show up in static HTML analysis. Requires manual confirmation.",
                                "Form snippet (truncated): " + summarize(formContent.trim(), 150),
                                "Implement CSRF protection (a synchronizer token, SameSite=Strict/Lax on session cookies, " +
                                        "or a custom header check) on every state-changing action (POST/PUT/DELETE)."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in CSRF check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }

    private String summarize(String text, int max) {
        if (text.length() <= max) return text;
        return text.substring(0, max) + "...";
    }
}
