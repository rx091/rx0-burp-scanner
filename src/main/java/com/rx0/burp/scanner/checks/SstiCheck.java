package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Server-Side Template Injection: injects math expressions in the syntax of
 * different template engines (Jinja2/Twig, ERB/Thymeleaf, EL, Freemarker)
 * and checks whether the EVALUATED result (e.g. "49" from 7*7) appears in
 * the response — compared against a payload-free baseline, to avoid false
 * positives from pages that already happened to contain "49".
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class SstiCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"name", "template", "q", "search", "message", "title"};

    // payload -> expected result if the template engine evaluates the expression
    private static final Map<String, String> PAYLOADS = new LinkedHashMap<>();
    static {
        PAYLOADS.put("{{7*7}}", "49");           // Jinja2, Twig
        PAYLOADS.put("${7*7}", "49");             // Freemarker, Velocity, JSP EL
        PAYLOADS.put("#{7*7}", "49");             // Thymeleaf, Ruby ERB
        PAYLOADS.put("<%= 7*7 %>", "49");         // ERB, EJS
        PAYLOADS.put("@(7*7)", "49");             // Razor (.NET)
        PAYLOADS.put("{{=7*7}}", "49");           // some JS engines
    }

    @Override
    public String name() {
        return "SSTI — Server-Side Template Injection";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            for (Map.Entry<String, String> entry : PAYLOADS.entrySet()) {
                try {
                    String payload = entry.getKey();
                    String expected = entry.getValue();

                    // Baseline: same parameter, with a neutral value that shouldn't produce "49"
                    String baselineUrl = base + "/?" + param + "=rx0_neutral_baseline";
                    HttpResponse baselineResp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(baselineUrl)).response();
                    boolean alreadyContained49 = baselineResp != null && baselineResp.bodyToString() != null
                            && baselineResp.bodyToString().contains(expected);
                    if (alreadyContained49) continue; // the page naturally already contains "49", skip this param to avoid a false positive

                    String payloadUrl = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                    HttpResponse payloadResp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(payloadUrl)).response();
                    if (payloadResp == null) continue;

                    String body = payloadResp.bodyToString();
                    if (body != null && body.contains(expected) && !body.contains(payload)) {
                        // contains the EVALUATED result (49) but not the raw payload — i.e. it was processed by the template engine
                        findings.add(new Finding(
                                "Possible SSTI in parameter '" + param + "'",
                                Severity.CRITICAL,
                                payloadUrl,
                                "The payload '" + payload + "' was sent and the response contains the evaluated result ('" + expected +
                                        "') instead of the raw payload — this indicates the value is processed by a template engine " +
                                        "on the server, which may allow remote code execution (RCE) depending on the engine.",
                                "Payload: " + payload + " | Evaluated result found: " + expected,
                                "Never pass user input directly into template rendering. Use pre-compiled templates with " +
                                        "data only as variables (never as code), and keep the template engine up to date.",
                                "1) Identify the exact engine: the payload '" + payload + "' that worked indicates which syntax is accepted. " +
                                        "2) Use PayloadsAllTheThings (SSTI) or tplmap (https://github.com/epinna/tplmap) pointed at " +
                                        "parameter '" + param + "' to automatically identify the engine and attempt RCE. 3) For Jinja2/Twig " +
                                        "(payload {{}}), try escalating to RCE with something like {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}} " +
                                        "(adjust for the correct engine). 4) Confirm the command output in the response — this is remote code execution."));
                        break; // confirmed on this param, no need to test the other syntaxes
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error in SSTI check (param " + param + "): " + e.getMessage());
                }
            }
        }
        return findings;
    }
}
