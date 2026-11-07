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
import java.util.Optional;

/**
 * Sends a forged Origin and checks whether the server reflects that Origin
 * back in Access-Control-Allow-Origin, especially alongside credentials=true.
 * Created by Rx0 - @rodrigocoutinho91
 */
public class CorsMisconfigCheck implements VulnCheck {

    private static final String FORGED_ORIGIN = "https://rx0-cors-test.evil.example";

    @Override
    public String name() {
        return "CORS configuration";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl)
                    .withAddedHeader("Origin", FORGED_ORIGIN);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return findings;

            Optional<HttpHeader> allowOrigin = resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Access-Control-Allow-Origin"))
                    .findFirst();
            Optional<HttpHeader> allowCreds = resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Access-Control-Allow-Credentials"))
                    .findFirst();

            if (allowOrigin.isPresent()) {
                String value = allowOrigin.get().value();
                boolean reflected = value.equals(FORGED_ORIGIN);
                boolean credentials = allowCreds.isPresent() && allowCreds.get().value().equalsIgnoreCase("true");

                if (reflected && credentials) {
                    findings.add(new Finding(
                            "Misconfigured CORS: Origin reflected with credentials=true",
                            Severity.CRITICAL, baseUrl,
                            "The server reflects any Origin sent and allows credentials, letting a malicious site read the victim's authenticated responses.",
                            "Origin sent: " + FORGED_ORIGIN + " | Access-Control-Allow-Origin: " + value
                                    + " | Access-Control-Allow-Credentials: true",
                            "Never dynamically reflect the Origin alongside credentials=true. Use a fixed allowlist of trusted origins.",
                            "1) Build a PoC HTML page (hosted on any domain, or locally) with a fetch() using " +
                                    "credentials: 'include' against " + baseUrl + " and print the response to the page (document.write(await resp.text())). " +
                                    "2) If the victim is logged in to the target site and visits your PoC page, the JS can read their " +
                                    "authenticated response (account data, tokens, etc) — this is a complete cross-origin session theft."));
                } else if (reflected) {
                    findings.add(new Finding(
                            "CORS reflects an arbitrary Origin",
                            Severity.MEDIUM, baseUrl,
                            "The server accepts and reflects any Origin in Access-Control-Allow-Origin.",
                            "Origin sent: " + FORGED_ORIGIN + " | Access-Control-Allow-Origin: " + value,
                            "Restrict Access-Control-Allow-Origin to a list of trusted origins."));
                } else if (value.equals("*") && credentials) {
                    findings.add(new Finding(
                            "CORS with wildcard (*) and credentials=true",
                            Severity.HIGH, baseUrl,
                            "This combination is invalid per spec, but when it occurs it indicates a dangerous configuration.",
                            "Access-Control-Allow-Origin: * | Allow-Credentials: true",
                            "Use an explicit origin (never *) whenever credentials are enabled."));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error in CORS check: " + e.getMessage());
        }
        return findings;
    }
}
