package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * LDAP Injection and XPath Injection — both detected via ERROR signatures
 * exposed when the parser/query engine receives an unexpected special
 * character (same approach as SqlErrorCheck, but for these two injection
 * types). Payloads are sent in typical login/search parameters.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class LdapXpathInjectionCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"username", "user", "login", "uid", "search", "filter", "q"};

    private static final String[] LDAP_PAYLOADS = {"*)(uid=*))(|(uid=*", "*)(|(password=*))", "admin*)((|userPassword=*)"};
    private static final String[] XPATH_PAYLOADS = {"' or '1'='1", "'] | //*[contains(*,'", "x' or 1=1 or 'x'='y"};

    private static final Pattern[] LDAP_SIGNATURES = {
            Pattern.compile("LDAPException", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javax\\.naming\\.directory", Pattern.CASE_INSENSITIVE),
            Pattern.compile("com\\.sun\\.jndi\\.ldap", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Invalid DN syntax", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Bad search filter", Pattern.CASE_INSENSITIVE),
    };

    private static final Pattern[] XPATH_SIGNATURES = {
            Pattern.compile("XPathException", Pattern.CASE_INSENSITIVE),
            Pattern.compile("com\\.sun\\.org\\.apache\\.xpath", Pattern.CASE_INSENSITIVE),
            Pattern.compile("MS\\.Internal\\.Xml\\.XPath", Pattern.CASE_INSENSITIVE),
            Pattern.compile("XPathEvalError", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Invalid expression|Invalid XPath", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String name() {
        return "LDAP Injection / XPath Injection (error-based)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            findings.addAll(test(api, base, param, LDAP_PAYLOADS, LDAP_SIGNATURES, "LDAP Injection"));
            findings.addAll(test(api, base, param, XPATH_PAYLOADS, XPATH_SIGNATURES, "XPath Injection"));
        }
        return findings;
    }

    private List<Finding> test(MontoyaApi api, String base, String param, String[] payloads,
                                Pattern[] signatures, String type) {
        List<Finding> findings = new ArrayList<>();
        for (String payload : payloads) {
            try {
                String url = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                for (Pattern p : signatures) {
                    if (p.matcher(body).find()) {
                        findings.add(new Finding(
                                "Possible " + type + " in parameter '" + param + "'",
                                Severity.CRITICAL,
                                url,
                                "Sending a " + type + " payload caused a characteristic error exposed in the response, " +
                                        "indicating the input is used directly in an " +
                                        (type.equals("LDAP Injection") ? "LDAP" : "XPath") + " query with no sanitization.",
                                "Payload: " + payload + " | Signature detected: " + p.pattern(),
                                type.equals("LDAP Injection")
                                        ? "Use LDAP APIs with bound parameters instead of concatenating strings into the search filter, and escape special LDAP characters (*, (, ), \\, NUL)."
                                        : "Use parameterized XPath queries (XPathExpression with variables) instead of concatenating user input into the expression.",
                                type.equals("LDAP Injection")
                                        ? "1) In Repeater, test an authentication bypass with a payload like *)(uid=*))(|(uid=* in the " +
                                          "username field of an LDAP login form. 2) If it authenticates without a valid password, that's a full bypass. " +
                                          "3) For data extraction, use blind LDAP injection with incremental boolean filters."
                                        : "1) Test a login bypass with payload ' or '1'='1 in the username field of a login that uses XML/XPath " +
                                          "as its data source. 2) For blind extraction, use payloads that test character by character " +
                                          "(e.g. substring(name,1,1)='a') and observe the behavioral difference."));
                        return findings; // already confirmed on this param+type
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in " + type + " check (param " + param + "): " + e.getMessage());
            }
        }
        return findings;
    }
}
