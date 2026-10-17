package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Tenta acessar endpoints de API comumente sensíveis SEM enviar nenhuma
 * credencial, procurando por respostas que pareçam dados reais (JSON) em
 * vez de 401/403 — um sinal clássico de Broken Authentication / BOLA
 * (OWASP API Security Top 10: API1 e API2).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class ApiEndpointDiscoveryCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/users", "/api/v1/users", "/api/v2/users",
            "/api/admin", "/api/v1/admin", "/api/internal",
            "/api/config", "/api/debug", "/api/health",
            "/api/accounts", "/api/customers", "/api/orders",
            "/api/v1/user/me", "/api/me", "/api/profile",
            "/api/v1/auth/users", "/api/private",
            "/.well-known/openid-configuration",
    };

    @Override
    public String nome() {
        return "Descoberta de endpoints de API sem autenticação";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(base + path)
                        .withAddedHeader("Accept", "application/json");
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                int status = resp.statusCode();
                if (status != 200) continue;

                Optional<HttpHeader> contentType = resp.headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                        .findFirst();
                boolean pareceJson = contentType.isPresent() && contentType.get().value().toLowerCase().contains("json");

                String body = resp.bodyToString();
                boolean temConteudo = body != null && body.trim().length() > 2
                        && (body.trim().startsWith("{") || body.trim().startsWith("["));

                if (pareceJson || temConteudo) {
                    achados.add(new Finding(
                            "Endpoint de API acessível sem autenticação: " + path,
                            Severity.ALTA,
                            base + path,
                            "A requisição sem nenhuma credencial retornou HTTP 200 com conteúdo que parece JSON de dados reais. " +
                                    "Isso pode indicar falha de autenticação (API1:2023 Broken Object Level Authorization / API2:2023 Broken Authentication). " +
                                    "Verifique manualmente se dados sensíveis estão de fato sendo expostos.",
                            "Status: 200 | Content-Type: " + contentType.map(HttpHeader::value).orElse("desconhecido")
                                    + " | Tamanho do corpo: " + (body != null ? body.length() : 0) + " bytes",
                            "Exija autenticação e autorização (verificação de ownership do recurso) em todo endpoint de API que retorne dados de usuário/negócio."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro ao checar endpoint de API " + path + ": " + e.getMessage());
            }
        }
        return achados;
    }
}
