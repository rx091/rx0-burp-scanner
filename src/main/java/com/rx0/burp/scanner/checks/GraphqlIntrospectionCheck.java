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
 * Looks for common GraphQL endpoints and tests whether schema introspection
 * is enabled in production — this exposes the entire API structure
 * (queries, mutations, internal types) to an attacker.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class GraphqlIntrospectionCheck implements VulnCheck {

    private static final String[] PATHS = {"/graphql", "/api/graphql", "/v1/graphql", "/graphql/console"};

    private static final String INTROSPECTION_QUERY =
            "{\"query\":\"query{__schema{queryType{name}mutationType{name}types{name kind}}}\"}";

    @Override
    public String name() {
        return "GraphQL introspection enabled";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(INTROSPECTION_QUERY);

                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (resp.statusCode() == 200 && body != null && body.contains("__schema") && body.contains("queryType")) {
                    int typeCount = countOccurrences(body, "\"kind\"");
                    findings.add(new Finding(
                            "GraphQL introspection enabled at " + path,
                            Severity.HIGH,
                            url,
                            "The GraphQL endpoint responds to the introspection query, exposing the entire schema structure " +
                                    "(types, queries, mutations) — valuable information for mapping the API and finding sensitive " +
                                    "fields or undocumented mutations.",
                            "Approximate number of types detected in the response: " + typeCount + " | Response contains '__schema' and 'queryType'.",
                            "Disable GraphQL introspection in production (or restrict it to authenticated/internal users)."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Error in GraphQL check (" + path + "): " + e.getMessage());
            }
        }
        return findings;
    }

    private int countOccurrences(String text, String snippet) {
        int count = 0, idx = 0;
        while ((idx = text.indexOf(snippet, idx)) != -1) {
            count++;
            idx += snippet.length();
        }
        return count;
    }
}
