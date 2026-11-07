package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.UUID;

/**
 * Calculates, ONCE per scan, a "baseline" by requesting a deliberately random,
 * nonexistent path. This detects the most common source of false positives in
 * path/endpoint scanners: SPA applications (React/Vue/Angular) or misconfigured
 * servers that respond HTTP 200 with the SAME page (usually index.html) for
 * ANY route (catch-all / soft-404).
 *
 * Checks that test paths (e.g. SensitivePathsCheck, ApiEndpointDiscoveryCheck)
 * use this guard to discard "findings" that are actually just this catch-all
 * behavior, rather than a real exposure.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class FalsePositiveGuard {

    private final boolean likelyCatchAll;
    private final int baselineStatus;
    private final int baselineSize;
    private final String contentSignature; // first 120 chars of the body, for quick comparison

    private FalsePositiveGuard(boolean likelyCatchAll, int baselineStatus, int baselineSize, String contentSignature) {
        this.likelyCatchAll = likelyCatchAll;
        this.baselineStatus = baselineStatus;
        this.baselineSize = baselineSize;
        this.contentSignature = contentSignature;
    }

    public static FalsePositiveGuard calculate(MontoyaApi api, String baseUrl) {
        try {
            String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
            String randomPath = "/rx0-path-that-does-not-exist-" + UUID.randomUUID().toString().substring(0, 12);

            HttpRequest req = HttpRequest.httpRequestFromUrl(base + randomPath);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) {
                return new FalsePositiveGuard(false, -1, -1, "");
            }

            String body = resp.bodyToString();
            int size = body == null ? 0 : body.length();
            String signature = body == null ? "" : body.substring(0, Math.min(120, body.length()));

            // If a RANDOM, NONEXISTENT path returns 200, the server likely has a
            // catch-all route (common in SPAs) — every path/endpoint check needs to
            // compare against this signature before reporting a finding.
            boolean catchAll = resp.statusCode() == 200;

            api.logging().logToOutput("[Rx0] False-positive baseline: status=" + resp.statusCode()
                    + " | catch-all detected=" + catchAll + " | body size=" + size);

            return new FalsePositiveGuard(catchAll, resp.statusCode(), size, signature);
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error calculating false-positive baseline: " + e.getMessage());
            return new FalsePositiveGuard(false, -1, -1, "");
        }
    }

    /**
     * @return true if the analyzed response matches the catch-all pattern detected
     *         in the baseline (i.e. it is likely a false positive, not a real
     *         exposure of that specific path).
     */
    public boolean looksLikeFalsePositive(int status, String body) {
        if (!likelyCatchAll) return false;
        if (status != baselineStatus) return false;

        int size = body == null ? 0 : body.length();
        String signature = body == null ? "" : body.substring(0, Math.min(120, body.length()));

        boolean similarSize = Math.abs(size - baselineSize) <= Math.max(40, (int) (baselineSize * 0.05));
        boolean sameSignature = signature.equals(contentSignature);

        return similarSize && sameSignature;
    }

    public boolean isLikelyCatchAll() {
        return likelyCatchAll;
    }
}
