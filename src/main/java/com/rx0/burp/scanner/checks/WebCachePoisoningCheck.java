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
 * Tests "unkeyed" headers (ones not part of the cache key but that can
 * affect the response's CONTENT) — if the server reflects the value of
 * these headers in the body/response AND there's a cache in front
 * (CDN/reverse proxy), a single malicious request can "poison" the cached
 * response for ALL subsequent visitors.
 *
 * This check detects the CONDITION (unkeyed header reflection + presence of
 * a cache) — confirming the poisoning actually took hold requires a second
 * request without the malicious header to see whether the malicious content
 * "stuck" to the cache, which is riskier to automate (it could affect real
 * visitors), so it's left as a manual validation step.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class WebCachePoisoningCheck implements VulnCheck {

    private static final String MARKER = "rx0cachetest" + (System.currentTimeMillis() % 100000);

    private static final String[] UNKEYED_HEADERS = {
            "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
            "X-Original-URL", "X-Rewrite-URL", "X-Host"
    };

    @Override
    public String name() {
        return "Web Cache Poisoning (unkeyed headers)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();

        // First, detect whether there's a cache in front (Cache-Control or CDN headers)
        boolean hasCache = detectCache(api, baseUrl);

        for (String header : UNKEYED_HEADERS) {
            try {
                String markedValue = header.toLowerCase().contains("scheme") || header.toLowerCase().contains("proto")
                        ? "rx0" + MARKER : MARKER + ".evil-rx0.test";

                HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl)
                        .withAddedHeader(header, markedValue);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                boolean reflected = body != null && body.contains(markedValue);

                if (reflected) {
                    findings.add(new Finding(
                            "Possible Web Cache Poisoning via header '" + header + "'" + (hasCache ? " (cache detected)" : ""),
                            hasCache ? Severity.HIGH : Severity.MEDIUM,
                            baseUrl,
                            "The header '" + header + "' (which normally is NOT part of CDNs'/proxies' cache key) was " +
                                    "reflected in the response body. " + (hasCache
                                    ? "Since there are signs of a cache in front of this target, this is a real risk condition: an " +
                                      "attacker can send a single request with a malicious payload in this header and the " +
                                      "poisoned response could get cached for ALL subsequent visitors."
                                    : "No clear signs of caching were detected on this target — the real impact depends on " +
                                      "whether a CDN/reverse proxy is caching by URL without considering this header, which needs " +
                                      "to be confirmed manually."),
                            "Header sent: " + header + ": " + markedValue + " | Reflected in the response body.",
                            "Configure the CDN/reverse proxy to include this header in the cache key (or normalize/strip it " +
                                    "before caching), and avoid having the application reflect request headers directly in HTML.",
                            "1) CAUTION: confirming this in practice can affect real site visitors, so only do this with " +
                                    "explicit authorization for this kind of test. 2) Send the request with the malicious header " +
                                    "ONCE, then send a NORMAL request (no header) to the same URL and check whether the " +
                                    "response still contains the malicious value — this confirms it got cached. 3) Use the " +
                                    "'X-Cache' or 'Age' response header to confirm whether it came from the cache or the origin."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in Cache Poisoning check (header " + header + "): " + e.getMessage());
            }
        }
        return findings;
    }

    private boolean detectCache(MontoyaApi api, String baseUrl) {
        try {
            HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(baseUrl)).response();
            if (resp == null) return false;
            for (HttpHeader h : resp.headers()) {
                String name = h.name().toLowerCase();
                if (name.equals("x-cache") || name.equals("cf-cache-status") || name.equals("age")
                        || name.equals("x-varnish") || name.equals("x-cdn") || name.equals("x-served-by")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            // proceed without detecting a cache
        }
        return false;
    }
}
