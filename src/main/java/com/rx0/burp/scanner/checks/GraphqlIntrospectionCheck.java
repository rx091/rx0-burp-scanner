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
 * Procura endpoints GraphQL comuns e testa se a introspecção do schema
 * está habilitada em produção — isso expõe toda a estrutura da API
 * (queries, mutations, tipos internos) para um atacante.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class GraphqlIntrospectionCheck implements VulnCheck {

    private static final String[] PATHS = {"/graphql", "/api/graphql", "/v1/graphql", "/graphql/console"};

    private static final String QUERY_INTROSPECCAO =
            "{\"query\":\"query{__schema{queryType{name}mutationType{name}types{name kind}}}\"}";

    @Override
    public String nome() {
        return "Introspecção GraphQL habilitada";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(QUERY_INTROSPECCAO);

                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (resp.statusCode() == 200 && body != null && body.contains("__schema") && body.contains("queryType")) {
                    int qtdTipos = contarOcorrencias(body, "\"kind\"");
                    achados.add(new Finding(
                            "Introspecção GraphQL habilitada em " + path,
                            Severity.ALTA,
                            url,
                            "O endpoint GraphQL responde à query de introspecção, expondo toda a estrutura do schema " +
                                    "(tipos, queries, mutations) — informação valiosa para mapear a API e encontrar campos sensíveis " +
                                    "ou mutations não documentadas.",
                            "Tipos aproximados detectados na resposta: " + qtdTipos + " | Resposta contém '__schema' e 'queryType'.",
                            "Desabilite a introspecção GraphQL em produção (ou restrinja a usuários autenticados/internos)."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de GraphQL (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }

    private int contarOcorrencias(String texto, String trecho) {
        int count = 0, idx = 0;
        while ((idx = texto.indexOf(trecho, idx)) != -1) {
            count++;
            idx += trecho.length();
        }
        return count;
    }
}
