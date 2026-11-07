package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;

/**
 * Checks whether cookies set by the server have the Secure, HttpOnly and SameSite flags.
 * Created by Rx0 - @rodrigocoutinho91
 */
public class CookieFlagsCheck implements VulnCheck {

    @Override
    public String name() {
        return "Cookie flags (Secure/HttpOnly/SameSite)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return findings;

            for (HttpHeader h : resp.headers()) {
                if (!h.name().equalsIgnoreCase("Set-Cookie")) continue;
                String cookie = h.value();
                String cookieName = cookie.split("=", 2)[0].trim();
                String lower = cookie.toLowerCase();

                if (!lower.contains("secure")) {
                    findings.add(new Finding(
                            "Cookie '" + cookieName + "' missing the Secure flag",
                            Severity.MEDIUM, baseUrl,
                            "The cookie can be transmitted over unencrypted HTTP connections.",
                            cookie,
                            "Add the Secure flag to the cookie to restrict it to HTTPS only."));
                }
                if (!lower.contains("httponly")) {
                    findings.add(new Finding(
                            "Cookie '" + cookieName + "' missing the HttpOnly flag",
                            Severity.MEDIUM, baseUrl,
                            "The cookie can be read via JavaScript (document.cookie), making theft via XSS easier.",
                            cookie,
                            "Add the HttpOnly flag to prevent access via JavaScript in the browser."));
                }
                if (!lower.contains("samesite")) {
                    findings.add(new Finding(
                            "Cookie '" + cookieName + "' missing the SameSite attribute",
                            Severity.LOW, baseUrl,
                            "Without SameSite, the cookie can be sent on cross-site requests, favoring CSRF.",
                            cookie,
                            "Set SameSite=Lax or Strict depending on the application's needs."));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error in cookies check: " + e.getMessage());
        }
        return findings;
    }
}
