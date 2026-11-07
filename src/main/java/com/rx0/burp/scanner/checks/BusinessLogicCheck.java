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

/**
 * BASIC business-logic heuristics on cart/checkout endpoints common in
 * e-commerce: tests whether the server accepts a negative quantity or an
 * altered price/value passed directly in the payload. This is a hard
 * category to automate generically (every application has its own logic),
 * so this is only an initial SIGNAL — it doesn't confirm exploitation, but
 * it points to where manual testing time is worth investing.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class BusinessLogicCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/cart", "/api/cart/add", "/api/carrinho", "/api/checkout",
            "/api/order", "/api/pedido", "/api/v1/cart/items"
    };

    @Override
    public String name() {
        return "Business logic (manipulable price/quantity)";
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl) {
        return execute(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> execute(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            findings.addAll(testNegativeQuantity(api, base, path, ctx));
            findings.addAll(testManipulatedPrice(api, base, path, ctx));
        }
        return findings;
    }

    private List<Finding> testNegativeQuantity(MontoyaApi api, String base, String path, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();
        try {
            String url = base + path;
            String requestBody = "{\"product_id\":1,\"productId\":1,\"id\":1,\"quantity\":-1,\"qty\":-1,\"quantidade\":-1}";

            HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                    .withMethod("POST")
                    .withAddedHeader("Content-Type", "application/json")
                    .withBody(requestBody);
            if (ctx != null) req = ctx.withAuth(req);

            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return findings;

            int status = resp.statusCode();
            if (status == 200 || status == 201) {
                String responseBody = resp.bodyToString();
                findings.add(new Finding(
                        "Endpoint accepted a negative quantity at " + path,
                        Severity.MEDIUM,
                        url,
                        "The endpoint returned HTTP " + status + " when given a negative quantity (-1) in the payload, instead " +
                                "of rejecting it with a validation error. If the application calculates the total based on this " +
                                "quantity, this could allow improperly reducing the cart/order's total value.",
                        "Status: " + status + " | Payload: " + requestBody
                                + (responseBody != null && responseBody.length() < 300 ? " | Response: " + responseBody : ""),
                        "Validate on the backend that quantity is always a positive integer greater than zero, and never trust " +
                                "total calculations coming from the client — always recompute them server-side.",
                        "1) Complete the flow through checkout with this negative quantity and check whether the order's " +
                                "total value goes negative or artificially reduces the amount due. 2) If the system has a " +
                                "balance/credit feature, test whether a 'purchase' with a negative total generates credit in the attacker's account."));
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error in negative quantity check (" + path + "): " + e.getMessage());
        }
        return findings;
    }

    private List<Finding> testManipulatedPrice(MontoyaApi api, String base, String path, ScanContext ctx) {
        List<Finding> findings = new ArrayList<>();
        try {
            String url = base + path;
            String requestBody = "{\"product_id\":1,\"productId\":1,\"id\":1,\"quantity\":1,\"price\":0.01,\"preco\":0.01,\"amount\":0.01,\"value\":0.01}";

            HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                    .withMethod("POST")
                    .withAddedHeader("Content-Type", "application/json")
                    .withBody(requestBody);
            if (ctx != null) req = ctx.withAuth(req);

            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return findings;

            int status = resp.statusCode();
            if (status != 200 && status != 201) return findings;

            String responseBody = resp.bodyToString();
            // Weak signal: whether the price we sent (0.01) appears echoed in the response as though it was accepted
            boolean priceEchoed = responseBody != null && (responseBody.contains("0.01") || responseBody.contains("\"price\":0.01"));

            if (priceEchoed) {
                findings.add(new Finding(
                        "Possible price manipulation accepted at " + path,
                        Severity.HIGH,
                        url,
                        "The endpoint accepted a price sent directly by the client ($0.01) and the response echoed that " +
                                "same value back, suggesting the item's price is trusted from the payload instead of being " +
                                "recomputed on the server from the real catalog.",
                        "Status: " + status + " | Payload: " + requestBody
                                + (responseBody != null && responseBody.length() < 300 ? " | Response: " + responseBody : ""),
                        "Never accept an item's price coming from the client. Always recompute the price on the server from " +
                                "the product ID looked up in the database/catalog.",
                        "1) Complete the checkout flow with this item and confirm whether the amount actually charged was $0.01 " +
                                "instead of the product's real price. 2) This is a classic e-commerce business-logic flaw — " +
                                "document it with before/after screenshots of the cart and the final amount charged."));
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Error in manipulated price check (" + path + "): " + e.getMessage());
        }
        return findings;
    }
}
