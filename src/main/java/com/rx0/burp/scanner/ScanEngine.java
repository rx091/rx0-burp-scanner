package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import com.rx0.burp.model.Finding;
import com.rx0.burp.scanner.checks.ApiEndpointDiscoveryCheck;
import com.rx0.burp.scanner.checks.BusinessLogicCheck;
import com.rx0.burp.scanner.checks.CookieFlagsCheck;
import com.rx0.burp.scanner.checks.CorsMisconfigCheck;
import com.rx0.burp.scanner.checks.CsrfTokenCheck;
import com.rx0.burp.scanner.checks.DirectoryListingCheck;
import com.rx0.burp.scanner.checks.DomXssCheck;
import com.rx0.burp.scanner.checks.ExcessiveDataExposureCheck;
import com.rx0.burp.scanner.checks.FileUploadCheck;
import com.rx0.burp.scanner.checks.GraphqlIntrospectionCheck;
import com.rx0.burp.scanner.checks.HostHeaderInjectionCheck;
import com.rx0.burp.scanner.checks.HttpMethodsCheck;
import com.rx0.burp.scanner.checks.IdorSequentialCheck;
import com.rx0.burp.scanner.checks.JwtWeaknessCheck;
import com.rx0.burp.scanner.checks.LdapXpathInjectionCheck;
import com.rx0.burp.scanner.checks.MassAssignmentCheck;
import com.rx0.burp.scanner.checks.NoSqlInjectionCheck;
import com.rx0.burp.scanner.checks.OpenRedirectCheck;
import com.rx0.burp.scanner.checks.OsCommandInjectionCheck;
import com.rx0.burp.scanner.checks.PathTraversalCheck;
import com.rx0.burp.scanner.checks.RateLimitCheck;
import com.rx0.burp.scanner.checks.ReflectedXssCheck;
import com.rx0.burp.scanner.checks.RfiCheck;
import com.rx0.burp.scanner.checks.SecurityHeadersCheck;
import com.rx0.burp.scanner.checks.SensitiveDataInBodyCheck;
import com.rx0.burp.scanner.checks.SensitivePathsCheck;
import com.rx0.burp.scanner.checks.SourceCodeDisclosureCheck;
import com.rx0.burp.scanner.checks.SqlErrorCheck;
import com.rx0.burp.scanner.checks.SsrfCheck;
import com.rx0.burp.scanner.checks.SstiCheck;
import com.rx0.burp.scanner.checks.StoredXssCheck;
import com.rx0.burp.scanner.checks.TechFingerprintCheck;
import com.rx0.burp.scanner.checks.VerboseApiErrorCheck;
import com.rx0.burp.scanner.checks.ViewStateAndAutocompleteCheck;
import com.rx0.burp.scanner.checks.WebCachePoisoningCheck;
import com.rx0.burp.scanner.checks.XxeCheck;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;

/**
 * Orchestrates the execution of every registered VulnCheck against a target host.
 *
 * Since the parallelization update: checks run concurrently in a fixed thread
 * pool (instead of one after another), which significantly reduces total scan
 * time. The thread count is deliberately moderate (6) to avoid overloading the
 * target or aggressively triggering rate-limiting/WAF defenses.
 *
 * Also calculates the FalsePositiveGuard and starts the InteractshClient
 * (out-of-band confirmation) ONCE per scan — both shared via ScanContext with
 * every check.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class ScanEngine {

    private static final int CONCURRENT_THREADS = 6;
    private static final int OOB_WAIT_SECONDS = 8;

    private final List<VulnCheck> checks;

    public ScanEngine() {
        this.checks = new ArrayList<>();
        // Central registry of every available check.
        // To add a new check in the future: create the class in scanner.checks
        // implementing VulnCheck and add a line here.
        checks.add(new SecurityHeadersCheck());
        checks.add(new CookieFlagsCheck());
        checks.add(new CorsMisconfigCheck());
        checks.add(new SensitivePathsCheck());
        checks.add(new ReflectedXssCheck());
        checks.add(new StoredXssCheck());
        checks.add(new DomXssCheck());
        checks.add(new SqlErrorCheck());
        checks.add(new OpenRedirectCheck());
        // --- API-focused checks (OWASP API Security Top 10) ---
        checks.add(new ApiEndpointDiscoveryCheck());
        checks.add(new IdorSequentialCheck());
        checks.add(new ExcessiveDataExposureCheck());
        checks.add(new GraphqlIntrospectionCheck());
        checks.add(new JwtWeaknessCheck());
        checks.add(new HttpMethodsCheck());
        checks.add(new RateLimitCheck());
        checks.add(new VerboseApiErrorCheck());
        // --- Injection / file inclusion / SSRF ---
        checks.add(new SsrfCheck());
        checks.add(new PathTraversalCheck());
        checks.add(new RfiCheck());
        checks.add(new NoSqlInjectionCheck());
        checks.add(new MassAssignmentCheck());
        // --- Based on the Burp Scanner check list (OS cmd, XXE, SSTI, LDAP/XPath...) ---
        checks.add(new OsCommandInjectionCheck());
        checks.add(new XxeCheck());
        checks.add(new SstiCheck());
        checks.add(new LdapXpathInjectionCheck());
        checks.add(new DirectoryListingCheck());
        checks.add(new SourceCodeDisclosureCheck());
        checks.add(new SensitiveDataInBodyCheck());
        checks.add(new CsrfTokenCheck());
        checks.add(new ViewStateAndAutocompleteCheck());
        // --- Further improvements: fingerprinting, host header, upload, cache poisoning, business logic ---
        checks.add(new TechFingerprintCheck());
        checks.add(new HostHeaderInjectionCheck());
        checks.add(new FileUploadCheck());
        checks.add(new WebCachePoisoningCheck());
        checks.add(new BusinessLogicCheck());
    }

    public int totalChecks() {
        return checks.size();
    }

    /** Backward-compatible variant (no authentication, no stealth mode). */
    public List<Finding> runFullScan(MontoyaApi api, String baseUrl, BiConsumer<String, Integer> progressCallback) {
        return runFullScan(api, baseUrl, progressCallback, null, false);
    }

    /**
     * Runs every check against the given base URL, in parallel.
     * @param api              Montoya API
     * @param baseUrl          normalized target URL (e.g. https://target.com)
     * @param progressCallback callback(finishedCheckName, completedCountSoFar) —
     *                         called when EACH check finishes (order is no
     *                         longer sequential due to parallelization)
     * @param authCookie       value to send in the Cookie header on every request
     *                         (e.g. "sessionid=abc123; other=value"), or null/empty
     *                         for an unauthenticated scan (the default behavior)
     * @param stealthMode      if true, runs with a single thread and a small delay
     *                         between checks, to reduce the chance of triggering
     *                         a WAF/rate-limit
     * @return consolidated, deduplicated list of findings from every check
     */
    public List<Finding> runFullScan(MontoyaApi api, String baseUrl, BiConsumer<String, Integer> progressCallback,
                                      String authCookie, boolean stealthMode) {
        List<Finding> allFindings = Collections.synchronizedList(new ArrayList<>());

        // Calculate the false-positive baseline, run the light crawler and start the OOB client, ONCE.
        FalsePositiveGuard guard = FalsePositiveGuard.calculate(api, baseUrl);
        LightCrawler crawler = LightCrawler.crawl(api, baseUrl);
        InteractshClient interactsh = InteractshClient.start(api);
        ScanContext ctx = new ScanContext(guard, interactsh, crawler, authCookie);

        AtomicInteger completed = new AtomicInteger(0);
        int threads = stealthMode ? 1 : Math.max(1, Math.min(CONCURRENT_THREADS, checks.size()));
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        for (VulnCheck check : checks) {
            pool.submit(() -> {
                try {
                    if (stealthMode) {
                        Thread.sleep(800); // small breather between checks in discreet mode
                    }
                    List<Finding> findings = check.execute(api, baseUrl, ctx);
                    allFindings.addAll(findings);
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Failed to run check '" + check.name() + "': " + e.getMessage());
                } finally {
                    int current = completed.incrementAndGet();
                    if (progressCallback != null) {
                        progressCallback.accept(check.name(), current);
                    }
                }
            });
        }

        pool.shutdown();
        try {
            boolean finishedInTime = pool.awaitTermination(10, TimeUnit.MINUTES);
            if (!finishedInTime) {
                api.logging().logToError("[Rx0] Scan exceeded the 10-minute time limit — partial results will be used.");
                pool.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            pool.shutdownNow();
        }

        // Collect findings confirmed via a real out-of-band interaction (SSRF/RFI/XXE/OS Command), if available.
        if (interactsh.isAvailable()) {
            if (progressCallback != null) {
                progressCallback.accept("Waiting for out-of-band confirmation (interactsh)...", checks.size());
            }
            try {
                List<Finding> oobFindings = interactsh.waitAndCollectInteractions(OOB_WAIT_SECONDS);
                allFindings.addAll(oobFindings);
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error collecting OOB interactions: " + e.getMessage());
            }
        }

        return deduplicate(new ArrayList<>(allFindings));
    }

    /**
     * Removes duplicate findings (same title + same URL) that different checks
     * or the OOB confirmation may have generated for the same underlying issue.
     * Keeps the first occurrence of each combination.
     */
    private List<Finding> deduplicate(List<Finding> findings) {
        Map<String, Finding> unique = new LinkedHashMap<>();
        for (Finding f : findings) {
            String key = f.getTitle() + "|" + f.getUrl();
            unique.putIfAbsent(key, f);
        }
        return new ArrayList<>(unique.values());
    }
}
