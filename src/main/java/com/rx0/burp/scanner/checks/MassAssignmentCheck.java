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
 * Sends, on typical registration/profile-update endpoints, EXTRA fields that
 * a regular user should never be able to set (isAdmin, role, verified,
 * balance, is_staff...) and checks whether the response ECHOES those fields
 * back with the privileged value we sent — a sign of Mass Assignment
 * (API6:2023 Unrestricted Access to Sensitive Business Flows / API3:2023
 * Broken Object Property Level Authorization).
 *
 * This is a signal, not a definitive confirmation: always manually verify
 * whether the field was actually persisted (e.g. by logging out and back in,
 * or by querying the resource in a second request).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class MassAssignmentCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/register", "/api/v1/register", "/api/users", "/api/signup",
            "/api/profile", "/api/me", "/api/account"
    };

    // privileged field name -> value we try to inject
    private static final String[][] PRIVILEGED_FIELDS = {
            {"isAdmin", "true"},
            {"is_admin", "true"},
            {"role", "\"admin\""},
            {"is_staff", "true"},
            {"verified", "true"},
            {"email_verified", "true"},
            {"balance", "999999"},
            {"credits", "999999"},
            {"plan", "\"enterprise\""},
    };

    @Override
    public String name() {
        return "Mass Assignment (privileged fields on registration/profile)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                String testUser = "rx0_mass_assign_" + (System.currentTimeMillis() % 1000000);

                StringBuilder body = new StringBuilder("{");
                body.append("\"username\":\"").append(testUser).append("\",");
                body.append("\"email\":\"").append(testUser).append("@rx0-test.invalid\",");
                body.append("\"password\":\"TestPassword123!\",");
                for (int i = 0; i < PRIVILEGED_FIELDS.length; i++) {
                    body.append("\"").append(PRIVILEGED_FIELDS[i][0]).append("\":").append(PRIVILEGED_FIELDS[i][1]);
                    if (i < PRIVILEGED_FIELDS.length - 1) body.append(",");
                }
                body.append("}");

                HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(body.toString());
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String respBody = resp.bodyToString();
                if (respBody == null || resp.statusCode() >= 400) continue;

                for (String[] field : PRIVILEGED_FIELDS) {
                    String fieldName = field[0];
                    String expectedValue = field[1].replace("\"", "");
                    Pattern p = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"?" + Pattern.quote(expectedValue) + "\"?",
                            Pattern.CASE_INSENSITIVE);
                    if (p.matcher(respBody).find()) {
                        findings.add(new Finding(
                                "Possible Mass Assignment: field '" + fieldName + "' accepted at " + path,
                                Severity.HIGH,
                                url,
                                "We sent the privileged field '" + fieldName + "' with value '" + expectedValue + "' alongside the registration, " +
                                        "and the response echoed that same value back — a sign the backend is assigning fields from the " +
                                        "JSON directly to the model/entity with no explicit allowlist of permitted fields.",
                                "Field tested: " + fieldName + "=" + expectedValue + " | Manually confirm whether it was actually persisted.",
                                "Never bind the received JSON directly to the database entity. Use explicit input DTOs " +
                                        "(field allowlist) and never accept changes to sensitive fields (role, isAdmin, balance) through a public endpoint.",
                                "1) Repeat the registration with user '" + testUser + "' and then try LOGGING IN with those credentials " +
                                        "(username: " + testUser + " / password: TestPassword123!). 2) Once logged in, access admin-restricted " +
                                        "functionality (admin panel, /api/admin/* endpoints) to confirm whether field '" + fieldName +
                                        "' really elevated the privilege. 3) This demonstrates full privilege escalation starting from a public signup."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in Mass Assignment check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }
}
