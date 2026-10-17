package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tenta acessar uma lista de paths comumente sensíveis (arquivos de config,
 * backups, .git, painéis admin, etc) e reporta os que respondem com 200/acesso.
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class SensitivePathsCheck implements VulnCheck {

    private static final Map<String, Severity> PATHS = new LinkedHashMap<>();
    static {
        PATHS.put("/.git/config", Severity.CRITICA);
        PATHS.put("/.git/HEAD", Severity.CRITICA);
        PATHS.put("/.env", Severity.CRITICA);
        PATHS.put("/.env.bak", Severity.CRITICA);
        PATHS.put("/wp-config.php.bak", Severity.CRITICA);
        PATHS.put("/config.php.bak", Severity.ALTA);
        PATHS.put("/backup.zip", Severity.ALTA);
        PATHS.put("/backup.sql", Severity.CRITICA);
        PATHS.put("/dump.sql", Severity.CRITICA);
        PATHS.put("/.DS_Store", Severity.BAIXA);
        PATHS.put("/phpinfo.php", Severity.ALTA);
        PATHS.put("/info.php", Severity.ALTA);
        PATHS.put("/server-status", Severity.MEDIA);
        PATHS.put("/.well-known/security.txt", Severity.INFO);
        PATHS.put("/swagger.json", Severity.MEDIA);
        PATHS.put("/swagger-ui.html", Severity.MEDIA);
        PATHS.put("/openapi.json", Severity.MEDIA);
        PATHS.put("/actuator/env", Severity.CRITICA);
        PATHS.put("/actuator/health", Severity.BAIXA);
        PATHS.put("/.htaccess", Severity.MEDIA);
        PATHS.put("/admin/", Severity.INFO);
        PATHS.put("/phpmyadmin/", Severity.MEDIA);
        PATHS.put("/robots.txt", Severity.INFO);
        PATHS.put("/sitemap.xml", Severity.INFO);
    }

    @Override
    public String nome() {
        return "Paths e arquivos sensíveis expostos";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (Map.Entry<String, Severity> entry : PATHS.entrySet()) {
            String path = entry.getKey();
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(base + path);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                int status = resp.statusCode();
                String body = resp.bodyToString();
                boolean vazio = body == null || body.isBlank();

                // Evita falso-positivo clássico de apps SPA que respondem 200 com a mesma home page pra tudo
                boolean pareceConteudoReal = !vazio && body.length() > 10;

                if (status == 200 && pareceConteudoReal) {
                    achados.add(new Finding(
                            "Path potencialmente sensível acessível: " + path,
                            entry.getValue(),
                            base + path,
                            "A URL respondeu HTTP 200. Confirme manualmente se o conteúdo retornado é realmente o arquivo/painel esperado (pode ser falso-positivo em SPAs com fallback de rota).",
                            "Status: " + status + " | Tamanho do corpo: " + body.length() + " bytes",
                            "Se o arquivo/painel não deveria estar público, remova-o ou restrinja o acesso por IP/autenticação."));
                } else if (status == 403) {
                    achados.add(new Finding(
                            "Path sensível existe mas está bloqueado (403): " + path,
                            Severity.INFO,
                            base + path,
                            "O recurso existe no servidor (retornou 403 em vez de 404), o que confirma sua presença mesmo que o acesso esteja negado.",
                            "Status: " + status,
                            "Mantenha o bloqueio e avalie remover o arquivo do diretório público quando possível."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro ao checar path " + path + ": " + e.getMessage());
            }
        }
        return achados;
    }
}
