package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;

/**
 * Light IDOR heuristic (API1:2023 Broken Object Level Authorization):
 * accesses sequential IDs on common API paths (/api/users/{id}, /api/orders/{id}...)
 * WITHOUT any credentials and checks whether DIFFERENT objects are returned with
 * 200, which suggests an absent ownership check. This is only a signal — it
 * requires manual validation, since the data may be public by design.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class IdorSequentialCheck implements VulnCheck {

    private static final String[] RESOURCES = {"/api/users/", "/api/v1/users/", "/api/orders/", "/api/accounts/"};
    private static final int[] IDS = {1, 2, 3};

    @Override
    public String name() {
        return "IDOR on API endpoints (sequential probe)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String resource : RESOURCES) {
            List<String> bodiesObtained = new ArrayList<>();
            List<String> successfulUrls = new ArrayList<>();

            for (int id : IDS) {
                try {
                    String url = base + resource + id;
                    HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                            .withAddedHeader("Accept", "application/json");
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    if (resp.statusCode() == 200) {
                        String body = resp.bodyToString();
                        if (body != null && body.trim().length() > 2
                                && (body.trim().startsWith("{") || body.trim().startsWith("["))) {
                            bodiesObtained.add(body);
                            successfulUrls.add(url);
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Error in IDOR probe (" + resource + id + "): " + e.getMessage());
                }
            }

            // If at least 2 different IDs returned 200 with DIFFERENT bodies from each other,
            // with no authentication at all, that's a strong sign of BOLA.
            if (bodiesObtained.size() >= 2) {
                boolean differentBodies = !bodiesObtained.get(0).equals(bodiesObtained.get(1));
                if (differentBodies) {
                    findings.add(new Finding(
                            "Possible IDOR / BOLA at " + resource + "{id}",
                            Severity.CRITICAL,
                            String.join(" , ", successfulUrls),
                            "Multiple sequential IDs returned HTTP 200 with DIFFERENT data objects from each other, with no " +
                                    "credentials sent at all. This suggests the endpoint does not validate whether the requester has " +
                                    "permission to access that specific object (Broken Object Level Authorization — API1:2023).",
                            "IDs tested: " + IDS.length + " | URLs with 200 and content: " + successfulUrls,
                            "Implement ownership/permission checks on every operation that receives an object ID, " +
                                    "and require authentication on those endpoints.",
                            "1) Open the URLs listed in the evidence in separate tabs and manually compare the returned data " +
                                    "(name, email, orders, etc) — confirm they belong to DIFFERENT people/records. 2) Test a wider ID range " +
                                    "(e.g. 1 to 100) to gauge how many records are exposed — this quantifies the real impact " +
                                    "(e.g. '847 users exposed' is stronger than 'looks vulnerable'). 3) If the data includes PII, document " +
                                    "this as a mass data leak, not just a technical flaw."));
                }
            }
        }
        return findings;
    }
}
