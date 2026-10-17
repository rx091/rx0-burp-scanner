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
 * Envia um JSON malformado / tipo de dado inesperado para endpoints de API
 * comuns e verifica se a resposta de erro expõe stack trace, caminho de
 * arquivo no servidor ou nome de framework — informação valiosa para um
 * atacante mapear a stack e encontrar outras falhas.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class VerboseApiErrorCheck implements VulnCheck {

    private static final String[] PATHS = {"/api/login", "/api/users", "/api/v1/users", "/api/search", "/api/orders"};
    private static final String CORPO_MALFORMADO = "{\"id\": {\"$ne\": null}, \"rx0\": }"; // JSON quebrado de propósito

    private static final Pattern[] ASSINATURAS = {
            Pattern.compile("at [\\w.$]+\\([\\w.]+\\.java:\\d+\\)"), // stack trace Java
            Pattern.compile("Traceback \\(most recent call last\\)"), // Python
            Pattern.compile("Fatal error:.*on line \\d+", Pattern.CASE_INSENSITIVE), // PHP
            Pattern.compile("System\\.\\w+Exception"), // .NET
            Pattern.compile("at Object\\.<anonymous>"), // Node.js
            Pattern.compile("/(usr|var|home|opt)/[\\w./-]+"), // caminho de arquivo Unix no corpo
            Pattern.compile("[A-Z]:\\\\\\\\[\\w\\\\.-]+"), // caminho de arquivo Windows
            Pattern.compile("\"stack\"\\s*:\\s*\"", Pattern.CASE_INSENSITIVE), // campo "stack" em JSON de erro
    };

    @Override
    public String nome() {
        return "Erros verbosos / stack trace em respostas de API";
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
                        .withBody(CORPO_MALFORMADO);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                for (Pattern p : ASSINATURAS) {
                    if (p.matcher(body).find()) {
                        achados.add(new Finding(
                                "Erro verboso expõe detalhes internos em " + path,
                                Severity.MEDIA,
                                url,
                                "O envio de um corpo JSON malformado causou uma resposta de erro que expõe stack trace, " +
                                        "caminho de arquivo no servidor ou nome de framework interno. Isso ajuda um atacante a mapear a " +
                                        "stack tecnológica e localizar outras vulnerabilidades.",
                                "Status: " + resp.statusCode() + " | Assinatura detectada: " + p.pattern(),
                                "Capture exceções no backend e retorne mensagens de erro genéricas para o cliente; logue o detalhe completo apenas server-side."));
                        break; // uma assinatura já basta pra esse path
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de erro verboso (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }
}
