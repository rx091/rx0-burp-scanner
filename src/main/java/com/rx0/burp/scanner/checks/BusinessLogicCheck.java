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
 * Heurísticas BÁSICAS de lógica de negócio em endpoints de carrinho/checkout
 * comuns em e-commerce: testa se o servidor aceita quantidade negativa ou
 * preço/valor alterado diretamente no payload. É uma categoria difícil de
 * automatizar de forma genérica (cada aplicação tem sua lógica própria),
 * então isso é só um SINAL inicial — não confirma exploração, mas aponta
 * pra onde vale investir tempo de teste manual.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class BusinessLogicCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/cart", "/api/cart/add", "/api/carrinho", "/api/checkout",
            "/api/order", "/api/pedido", "/api/v1/cart/items"
    };

    @Override
    public String nome() {
        return "Lógica de negócio (preço/quantidade manipulável)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        return executar(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            achados.addAll(testarQuantidadeNegativa(api, base, path, ctx));
            achados.addAll(testarPrecoManipulado(api, base, path, ctx));
        }
        return achados;
    }

    private List<Finding> testarQuantidadeNegativa(MontoyaApi api, String base, String path, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();
        try {
            String url = base + path;
            String corpo = "{\"product_id\":1,\"productId\":1,\"id\":1,\"quantity\":-1,\"qty\":-1,\"quantidade\":-1}";

            HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                    .withMethod("POST")
                    .withAddedHeader("Content-Type", "application/json")
                    .withBody(corpo);
            if (ctx != null) req = ctx.comAuth(req);

            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return achados;

            int status = resp.statusCode();
            if (status == 200 || status == 201) {
                String body = resp.bodyToString();
                achados.add(new Finding(
                        "Endpoint aceitou quantidade negativa em " + path,
                        Severity.MEDIA,
                        url,
                        "O endpoint retornou HTTP " + status + " ao receber uma quantidade negativa (-1) no payload, em vez " +
                                "de rejeitar com erro de validação. Se a aplicação calcular o total com base nessa quantidade, " +
                                "isso pode permitir reduzir o valor total do carrinho/pedido de forma indevida.",
                        "Status: " + status + " | Payload: " + corpo
                                + (body != null && body.length() < 300 ? " | Resposta: " + body : ""),
                        "Valide no backend que quantidade seja sempre um inteiro positivo maior que zero, e nunca confie em " +
                                "cálculos de total vindos do cliente — recalcule sempre no servidor.",
                        "1) Complete o fluxo até o checkout com essa quantidade negativa e veja se o valor total do pedido " +
                                "fica negativo ou reduz artificialmente o total a pagar. 2) Se o sistema tiver saldo/crédito, " +
                                "teste se uma 'compra' com total negativo gera crédito na conta do atacante."));
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro no check de quantidade negativa (" + path + "): " + e.getMessage());
        }
        return achados;
    }

    private List<Finding> testarPrecoManipulado(MontoyaApi api, String base, String path, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();
        try {
            String url = base + path;
            String corpo = "{\"product_id\":1,\"productId\":1,\"id\":1,\"quantity\":1,\"price\":0.01,\"preco\":0.01,\"amount\":0.01,\"valor\":0.01}";

            HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                    .withMethod("POST")
                    .withAddedHeader("Content-Type", "application/json")
                    .withBody(corpo);
            if (ctx != null) req = ctx.comAuth(req);

            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return achados;

            int status = resp.statusCode();
            if (status != 200 && status != 201) return achados;

            String body = resp.bodyToString();
            // Sinal fraco: se o preço que enviamos (0.01) aparece ecoado na resposta como se tivesse sido aceito
            boolean precoEcoado = body != null && (body.contains("0.01") || body.contains("\"price\":0.01"));

            if (precoEcoado) {
                achados.add(new Finding(
                        "Possível manipulação de preço aceita em " + path,
                        Severity.ALTA,
                        url,
                        "O endpoint aceitou um preço enviado diretamente pelo cliente (R$ 0,01) e a resposta ecoou esse " +
                                "mesmo valor, sugerindo que o preço do item é confiado a partir do payload em vez de ser " +
                                "recalculado no servidor a partir do catálogo real.",
                        "Status: " + status + " | Payload: " + corpo
                                + (body != null && body.length() < 300 ? " | Resposta: " + body : ""),
                        "Nunca aceite o preço do item vindo do cliente. Sempre recalcule o preço no servidor a partir do " +
                                "ID do produto consultado no banco de dados/catálogo.",
                        "1) Complete o fluxo de checkout com esse item e confirme se o valor cobrado realmente foi R$ 0,01 " +
                                "em vez do preço real do produto. 2) Isso é uma falha de lógica de negócio clássica em " +
                                "e-commerce — documente com prints do carrinho antes/depois e o valor final cobrado."));
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro no check de preço manipulado (" + path + "): " + e.getMessage());
        }
        return achados;
    }
}
