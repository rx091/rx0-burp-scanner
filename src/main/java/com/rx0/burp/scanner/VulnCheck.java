package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import com.rx0.burp.model.Finding;

import java.util.List;

/**
 * Contract every vulnerability check must implement.
 * Each check receives the target base URL and returns 0..N findings.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public interface VulnCheck {

    /** Name of the check, shown in the progress log. */
    String name();

    /**
     * Runs the check against the given base URL.
     * @param api     Montoya API instance (for logging and HTTP requests)
     * @param baseUrl target URL, e.g. https://target.com
     * @return list of findings (may be empty)
     */
    List<Finding> execute(MontoyaApi api, String baseUrl);

    /**
     * False-positive-aware variant: receives the {@link FalsePositiveGuard} already
     * calculated once for the whole scan. Checks that test paths/endpoints (where the
     * risk of false positives from catch-all/SPA routing is higher) should override
     * this method and use the guard to filter findings before returning them. Checks
     * that don't benefit from this (XSS, SQLi, headers...) don't need to override it —
     * the default simply ignores the guard and calls the regular execute(api, baseUrl).
     */
    default List<Finding> execute(MontoyaApi api, String baseUrl, FalsePositiveGuard guard) {
        return execute(api, baseUrl);
    }

    /**
     * {@link ScanContext}-aware variant (guard + interactsh client). Checks that want
     * to register out-of-band confirmation probes (SSRF, RFI, XXE, OS Command Injection)
     * should override this method and use ctx.interactsh(). The default simply delegates
     * to the guard-aware variant, preserving the behavior of every check that existed
     * before ScanContext was introduced.
     */
    default List<Finding> execute(MontoyaApi api, String baseUrl, ScanContext ctx) {
        return execute(api, baseUrl, ctx.guard());
    }
}
