package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.FalsePositiveGuard;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Testa diretórios comuns em busca de Directory Listing habilitado
 * (o servidor lista o conteúdo da pasta em vez de servir um index/404).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class DirectoryListingCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/images/", "/img/", "/uploads/", "/upload/", "/files/", "/file/",
            "/backup/", "/backups/", "/assets/", "/static/", "/media/", "/tmp/", "/logs/"
    };

    private static final Pattern[] ASSINATURAS = {
            Pattern.compile("Index of /", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<title>Directory listing for", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\[To Parent Directory\\]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<h1>Index of", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String nome() {
        return "Directory Listing habilitado";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        return executar(api, baseUrl, FalsePositiveGuard.calcular(api, baseUrl));
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl, FalsePositiveGuard guard) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;
                if (guard.pareceFalsoPositivo(resp.statusCode(), body)) continue;

                for (Pattern p : ASSINATURAS) {
                    if (p.matcher(body).find()) {
                        achados.add(new Finding(
                                "Directory Listing habilitado em " + path,
                                Severity.INFO,
                                url,
                                "O servidor lista o conteúdo do diretório em vez de retornar um index/404, expondo a estrutura " +
                                        "de arquivos e potencialmente arquivos não destinados a acesso público.",
                                "Assinatura encontrada: " + p.pattern(),
                                "Desabilite a listagem de diretórios no servidor web (ex: 'Options -Indexes' no Apache, " +
                                        "'autoindex off;' no Nginx) e coloque um arquivo index vazio em pastas públicas se necessário."));
                        break;
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de Directory Listing (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }
}
