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
 * Heurística leve de IDOR (API1:2023 Broken Object Level Authorization):
 * acessa IDs sequenciais em paths de API comuns (/api/users/{id}, /api/orders/{id}...)
 * SEM nenhuma credencial e verifica se objetos DIFERENTES são retornados com 200,
 * o que sugere ausência de checagem de ownership. É apenas um sinal — requer
 * validação manual, pois pode ser dado público por design.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class IdorSequentialCheck implements VulnCheck {

    private static final String[] RECURSOS = {"/api/users/", "/api/v1/users/", "/api/orders/", "/api/accounts/"};
    private static final int[] IDS = {1, 2, 3};

    @Override
    public String nome() {
        return "IDOR em endpoints de API (probe sequencial)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String recurso : RECURSOS) {
            List<String> corposObtidos = new ArrayList<>();
            List<String> urlsComSucesso = new ArrayList<>();

            for (int id : IDS) {
                try {
                    String url = base + recurso + id;
                    HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                            .withAddedHeader("Accept", "application/json");
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    if (resp.statusCode() == 200) {
                        String body = resp.bodyToString();
                        if (body != null && body.trim().length() > 2
                                && (body.trim().startsWith("{") || body.trim().startsWith("["))) {
                            corposObtidos.add(body);
                            urlsComSucesso.add(url);
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro no probe de IDOR (" + recurso + id + "): " + e.getMessage());
                }
            }

            // Se pelo menos 2 IDs diferentes retornaram 200 com corpos DIFERENTES entre si,
            // sem nenhuma autenticação, é um forte indício de BOLA.
            if (corposObtidos.size() >= 2) {
                boolean corposDiferentes = !corposObtidos.get(0).equals(corposObtidos.get(1));
                if (corposDiferentes) {
                    achados.add(new Finding(
                            "Possível IDOR / BOLA em " + recurso + "{id}",
                            Severity.CRITICA,
                            String.join(" , ", urlsComSucesso),
                            "Múltiplos IDs sequenciais retornaram HTTP 200 com objetos de dados DIFERENTES entre si, sem envio de " +
                                    "nenhuma credencial. Isso sugere que o endpoint não valida se o solicitante tem permissão para " +
                                    "acessar aquele objeto específico (Broken Object Level Authorization — API1:2023).",
                            "IDs testados: " + IDS.length + " | URLs com 200 e conteúdo: " + urlsComSucesso,
                            "Implemente verificação de ownership/permissão em toda operação que recebe um ID de objeto, " +
                                    "e exija autenticação nesses endpoints."));
                }
            }
        }
        return achados;
    }
}
