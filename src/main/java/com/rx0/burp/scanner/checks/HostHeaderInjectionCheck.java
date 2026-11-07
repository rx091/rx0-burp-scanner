package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Tests whether the server blindly trusts the Host header (or
 * X-Forwarded-Host) sent by the client — this can lead to cache poisoning,
 * host-based access control bypass, poisoned password reset links (when the
 * email uses the Host to build the URL), and in some cases internal SSRF.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class HostHeaderInjectionCheck implements VulnCheck {

    private static final String FORGED_HOST = "rx0-host-header-test.invalid";

    @Override
    public String name() {
        return "Host Header Injection";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testHeader(api, baseUrl, "Host", ctx));
        findings.addAll(testHeader(api, baseUrl, "X-Forwarded-Host", ctx));

        return findings;
    }

    private List<Finding> testHeader(MontoyaApi api, String baseUrl, String headerName, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl);
            // For a real "Host" override, Burp controls this via httpService; we also simulate via an extra header many apps honor
            req = req.withAddedHeader(headerName, FORGED_HOST);
            if (ctx != null) req = ctx.withAuth(req);

            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return findings;

            String body = resp.bodyToString();
            boolean reflectedInBody = body != null && body.contains(FORGED_HOST);

            Optional<HttpHeader> location = resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Location"))
                    .findFirst();
            boolean reflectedInRedirect = location.isPresent() && location.get().value().contains(FORGED_HOST);

            if (reflectedInBody || reflectedInRedirect) {
                findings.add(new Finding(
                        "Host Header Injection via '" + headerName + "'",
                        Severity.MEDIUM,
                        baseUrl,
                        "The server reflected the forged value of the '" + headerName + "' header " +
                                (reflectedInRedirect ? "in a redirect (Location)" : "in the response body") +
                                " without validating whether it's an expected host. This can be abused for cache " +
                                "poisoning, crafting malicious links (e.g. a password-reset email with a forged domain), or " +
                                "in some cases internal SSRF if the value is used in server-side calls.",
                        "Header sent: " + headerName + ": " + FORGED_HOST + " | " +
                                (reflectedInRedirect ? "Location: " + location.get().value() : "Reflected in the response body"),
                        "Validate the Host/X-Forwarded-Host header against an allowlist of expected domains at the load " +
                                "balancer/reverse proxy, never trust it to build absolute URLs without validation.",
                        "1) If you found reflection in a password-reset email: sign up with this forged header during the " +
                                "'forgot my password' flow and check whether the link sent to the email points at the forged domain — " +
                                "this allows account takeover by intercepting the victim's click. 2) Also test whether it affects " +
                                "cache generation (web cache poisoning) by sending the same request again without the forged header " +
                                "and checking whether the malicious content persists for other visitors."));
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error in Host Header Injection check (" + headerName + "): " + e.getMessage());
        }
        return findings;
    }
}
