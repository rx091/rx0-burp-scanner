package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Testa se o servidor confia cegamente no header Host (ou X-Forwarded-Host)
 * enviado pelo cliente — isso pode levar a cache poisoning, bypass de
 * controle de acesso baseado em host, envenenamento de link de reset de
 * senha (quando o e-mail usa o Host pra montar a URL), e SSRF interno em
 * alguns casos.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class HostHeaderInjectionCheck implements VulnCheck {

    private static final String HOST_FORJADO = "rx0-host-header-test.invalid";

    @Override
    public String nome() {
        return "Host Header Injection";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        return executar(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();

        achados.addAll(testarHeader(api, baseUrl, "Host", ctx));
        achados.addAll(testarHeader(api, baseUrl, "X-Forwarded-Host", ctx));

        return achados;
    }

    private List<Finding> testarHeader(MontoyaApi api, String baseUrl, String nomeHeader, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl);
            // Para "Host" de verdade, o Burp controla isso via httpService; simulamos via header extra também aceito por muitos apps
            req = req.withAddedHeader(nomeHeader, HOST_FORJADO);
            if (ctx != null) req = ctx.comAuth(req);

            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return achados;

            String body = resp.bodyToString();
            boolean refletidoNoCorpo = body != null && body.contains(HOST_FORJADO);

            Optional<HttpHeader> location = resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Location"))
                    .findFirst();
            boolean refletidoNoRedirect = location.isPresent() && location.get().value().contains(HOST_FORJADO);

            if (refletidoNoCorpo || refletidoNoRedirect) {
                achados.add(new Finding(
                        "Host Header Injection via '" + nomeHeader + "'",
                        Severity.MEDIA,
                        baseUrl,
                        "O servidor refletiu o valor forjado do header '" + nomeHeader + "' " +
                                (refletidoNoRedirect ? "em um redirecionamento (Location)" : "no corpo da resposta") +
                                " sem validar se é um host esperado. Isso pode ser abusado pra envenenamento de cache, " +
                                "montagem de links maliciosos (ex: e-mail de reset de senha com domínio forjado), ou em " +
                                "alguns casos SSRF interno se o valor for usado em chamadas server-side.",
                        "Header enviado: " + nomeHeader + ": " + HOST_FORJADO + " | " +
                                (refletidoNoRedirect ? "Location: " + location.get().value() : "Refletido no corpo da resposta"),
                        "Valide o header Host/X-Forwarded-Host contra uma allowlist de domínios esperados no load balancer/proxy " +
                                "reverso, nunca confie nele para montar URLs absolutas sem validação.",
                        "1) Se achou reflexo em e-mail de reset de senha: cadastre-se com esse header forjado durante o fluxo de " +
                                "'esqueci minha senha' e veja se o link enviado ao e-mail aponta pro domínio forjado — isso permite " +
                                "sequestro de conta interceptando o clique da vítima. 2) Teste também se afeta geração de cache " +
                                "(web cache poisoning) enviando a mesma requisição de novo sem o header forjado e vendo se o " +
                                "conteúdo malicioso persiste pra outros visitantes."));
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro no check de Host Header Injection (" + nomeHeader + "): " + e.getMessage());
        }
        return achados;
    }
}
