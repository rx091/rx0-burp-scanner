package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Sends a single-quote character in common parameters and looks for database
 * error signatures in the response (error-based SQLi). A light probe, does
 * not perform exploitation — only detects verbose error output.
 * Created by Rx0 - @rodrigocoutinho91
 */
public class SqlErrorCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"id", "user", "product", "category", "page", "item"};
    private static final String[] PAYLOADS = {"'", "\"", "1'\"", "') OR ('1'='1"};

    private static final Pattern[] ERROR_SIGNATURES = {
            Pattern.compile("SQL syntax.*MySQL", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Warning.*mysqli?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("PostgreSQL.*ERROR", Pattern.CASE_INSENSITIVE),
            Pattern.compile("ORA-\\d{5}"),
            Pattern.compile("Microsoft OLE DB Provider for SQL Server"),
            Pattern.compile("Unclosed quotation mark after the character string"),
            Pattern.compile("SQLite3?::", Pattern.CASE_INSENSITIVE),
            Pattern.compile("System\\.Data\\.SqlClient"),
            Pattern.compile("PDOException", Pattern.CASE_INSENSITIVE)
    };

    @Override
    public String name() {
        return "Exposed SQL errors (light probe)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            for (String payload : PAYLOADS) {
                try {
                    String testUrl = base + "/?" + param + "=" + java.net.URLEncoder.encode(payload, "UTF-8");
                    HttpRequest req = HttpRequest.httpRequestFromUrl(testUrl);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body == null) continue;

                    for (Pattern p : ERROR_SIGNATURES) {
                        if (p.matcher(body).find()) {
                            findings.add(new Finding(
                                    "Possible SQL Injection (exposed error) in parameter '" + param + "'",
                                    Severity.CRITICAL,
                                    testUrl,
                                    "Sending a payload with a special character caused a database error visible in the response, indicating the input is not sanitized before the query.",
                                    "Payload: " + payload + " | Signature detected: " + p.pattern(),
                                    "Use prepared statements / parameterized queries throughout the application and disable verbose error messages in production.",
                                    "1) Open Burp Repeater and resend the URL: " + testUrl + " 2) Confirm the database error in the response. " +
                                            "3) To advance the exploitation, try UNION-based injection (e.g. ' UNION SELECT NULL,NULL-- -, adjusting the column count) " +
                                            "or use sqlmap pointed at this parameter: sqlmap -u \"" + testUrl + "\" --batch --dbs " +
                                            "4) Always in an authorized environment — this can extract data from the database."));
                            // already found a signature for this param+payload, no need to test the other signatures
                            break;
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error in SQLi check (param " + param + "): " + e.getMessage());
                }
            }
        }
        return findings;
    }
}
