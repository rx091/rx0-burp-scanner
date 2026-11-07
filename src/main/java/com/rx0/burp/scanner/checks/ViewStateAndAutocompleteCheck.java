package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Two static checks related to legacy/ASP.NET forms:
 *  - ASP.NET ViewState present WITHOUT __VIEWSTATEMAC — allows ViewState
 *    tampering (can lead to insecure deserialization, depending on the version).
 *  - A <input type="password"> field with no autocomplete="off"/"new-password" —
 *    the browser may save the password in cache/autofill insecurely on
 *    shared devices.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class ViewStateAndAutocompleteCheck implements VulnCheck {

    private static final String[] PATHS = {"/", "/login", "/signin", "/account/login"};

    private static final Pattern VIEWSTATE_PATTERN = Pattern.compile("name=[\"']__VIEWSTATE[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern VIEWSTATEMAC_PATTERN = Pattern.compile("name=[\"']__VIEWSTATEMAC[\"']", Pattern.CASE_INSENSITIVE);

    private static final Pattern PASSWORD_FIELD_PATTERN = Pattern.compile("<input\\b[^>]*type=[\"']password[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern AUTOCOMPLETE_OFF_PATTERN = Pattern.compile("autocomplete=[\"'](off|new-password)[\"']", Pattern.CASE_INSENSITIVE);

    @Override
    public String name() {
        return "ASP.NET ViewState with no MAC / password autocomplete";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
                if (resp == null || resp.statusCode() != 200) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                // --- ViewState with no MAC ---
                if (VIEWSTATE_PATTERN.matcher(body).find() && !VIEWSTATEMAC_PATTERN.matcher(body).find()) {
                    findings.add(new Finding(
                            "ASP.NET ViewState with MAC disabled",
                            Severity.HIGH,
                            url,
                            "The page uses __VIEWSTATE (ASP.NET Web Forms) but has no __VIEWSTATEMAC. Without the MAC, the " +
                                    "ViewState can be tampered with by the client undetected, and depending on the .NET version " +
                                    "this can open the door to insecure deserialization (ViewState deserialization RCE).",
                            "__VIEWSTATE found, __VIEWSTATEMAC absent.",
                            "Enable EnableViewStateMac=true (this is the default in recent .NET versions — confirm it wasn't disabled) " +
                                    "and keep the framework up to date."));
                }

                // --- Autocomplete on password field ---
                Matcher passwordFieldMatcher = PASSWORD_FIELD_PATTERN.matcher(body);
                int index = 0;
                while (passwordFieldMatcher.find()) {
                    index++;
                    String fullTag = passwordFieldMatcher.group();
                    if (!AUTOCOMPLETE_OFF_PATTERN.matcher(fullTag).find()) {
                        findings.add(new Finding(
                                "Password field with no autocomplete=\"off\"/\"new-password\" (field #" + index + ") at " + path,
                                Severity.LOW,
                                url,
                                "The password field does not disable browser autocomplete. On shared/public devices, " +
                                        "this can let the password be saved in the browser's autofill.",
                                "Tag found: " + summarize(fullTag, 120),
                                "Add autocomplete=\"new-password\" (currently recommended by browsers) to the password field."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in ViewState/autocomplete check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }

    private String summarize(String text, int max) {
        if (text.length() <= max) return text;
        return text.substring(0, max) + "...";
    }
}
