package com.rx0.burp.scanner;

/**
 * Groups the resources shared by every check within the same scan:
 * the false-positive guard (catch-all/SPA detection) and the interactsh
 * client (out-of-band confirmation). Calculated/started ONCE per scan in
 * ScanEngine and passed to every check — any check can ignore what it
 * doesn't use.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class ScanContext {

    private final FalsePositiveGuard guard;
    private final InteractshClient interactsh;
    private final LightCrawler crawler;
    private final String authCookie; // may be null/empty — unauthenticated scan

    public ScanContext(FalsePositiveGuard guard, InteractshClient interactsh, LightCrawler crawler, String authCookie) {
        this.guard = guard;
        this.interactsh = interactsh;
        this.crawler = crawler;
        this.authCookie = authCookie;
    }

    public FalsePositiveGuard guard() {
        return guard;
    }

    public InteractshClient interactsh() {
        return interactsh;
    }

    public LightCrawler crawler() {
        return crawler;
    }

    /** @return the Cookie header value to apply on requests, or null if not configured. */
    public String authCookie() {
        return (authCookie == null || authCookie.isBlank()) ? null : authCookie;
    }

    public boolean hasAuth() {
        return authCookie() != null;
    }

    /** Applies the auth cookie (if configured) to a request. Usage: req = ctx.withAuth(req). */
    public burp.api.montoya.http.message.requests.HttpRequest withAuth(burp.api.montoya.http.message.requests.HttpRequest req) {
        if (hasAuth()) {
            return req.withAddedHeader("Cookie", authCookie());
        }
        return req;
    }
}
