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
 * Testa variações de backup/editor em cima de nomes de arquivo comuns
 * (index, config, login, database, admin) com extensões que fazem o
 * servidor servir o CÓDIGO-FONTE em vez de executá-lo (.bak, ~, .swp,
 * .orig, .old) — um clássico de servidor mal configurado após deploy
 * ou edição direta no servidor.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class SourceCodeDisclosureCheck implements VulnCheck {

    private static final String[] NOMES_BASE = {"index", "config", "login", "database", "db", "admin", "connect", "settings"};
    private static final String[] EXTENSOES_BASE = {".php", ".asp", ".aspx", ".jsp", ".java"};
    private static final String[] SUFIXOS_BACKUP = {".bak", "~", ".swp", ".orig", ".old", ".save", ".1"};

    private static final Pattern[] ASSINATURAS_CODIGO = {
            Pattern.compile("<\\?php"),
            Pattern.compile("import\\s+java\\.|package\\s+[\\w.]+;"),
            Pattern.compile("using\\s+System;|namespace\\s+\\w+"),
            Pattern.compile("<%@\\s*page"), // JSP
            Pattern.compile("require\\(|include\\(|function\\s+\\w+\\s*\\("),
            Pattern.compile("SELECT\\s+.+\\s+FROM\\s+", Pattern.CASE_INSENSITIVE), // SQL embutido em config
    };

    @Override
    public String nome() {
        return "Código-fonte / arquivo de backup exposto";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        return executar(api, baseUrl, FalsePositiveGuard.calcular(api, baseUrl));
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl, FalsePositiveGuard guard) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String nomeBase : NOMES_BASE) {
            for (String extensao : EXTENSOES_BASE) {
                for (String sufixo : SUFIXOS_BACKUP) {
                    try {
                        String path = "/" + nomeBase + extensao + sufixo;
                        String url = base + path;
                        HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
                        if (resp == null || resp.statusCode() != 200) continue;

                        String body = resp.bodyToString();
                        if (body == null || body.isBlank()) continue;
                        if (guard.pareceFalsoPositivo(resp.statusCode(), body)) continue;

                        for (Pattern p : ASSINATURAS_CODIGO) {
                            if (p.matcher(body).find()) {
                                achados.add(new Finding(
                                        "Código-fonte exposto: " + path,
                                        Severity.CRITICA,
                                        url,
                                        "Um arquivo de backup/editor foi encontrado publicamente acessível e contém código-fonte " +
                                                "do lado do servidor (em vez de ser executado, foi servido como texto puro) — isso pode " +
                                                "expor lógica de negócio, credenciais hardcoded e detalhes de implementação.",
                                        "Assinatura de código encontrada: " + p.pattern() + " | Tamanho do corpo: " + body.length() + " bytes",
                                        "Remova arquivos de backup/temporários do diretório público do servidor web, e configure o editor " +
                                                "(ex: vim) para não deixar arquivos .swp na pasta do projeto em produção."));
                                break;
                            }
                        }
                    } catch (Exception e) {
                        api.logging().logToError("[Rx0] Erro no check de source code disclosure: " + e.getMessage());
                    }
                }
            }
        }
        return achados;
    }
}
