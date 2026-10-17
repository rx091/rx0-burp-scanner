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

/**
 * Verifica se os cookies setados pelo servidor possuem as flags Secure, HttpOnly e SameSite.
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class CookieFlagsCheck implements VulnCheck {

    @Override
    public String nome() {
        return "Flags de cookies (Secure/HttpOnly/SameSite)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return achados;

            for (HttpHeader h : resp.headers()) {
                if (!h.name().equalsIgnoreCase("Set-Cookie")) continue;
                String cookie = h.value();
                String nomeCookie = cookie.split("=", 2)[0].trim();
                String lower = cookie.toLowerCase();

                if (!lower.contains("secure")) {
                    achados.add(new Finding(
                            "Cookie '" + nomeCookie + "' sem flag Secure",
                            Severity.MEDIA, baseUrl,
                            "O cookie pode ser transmitido em conexões HTTP não criptografadas.",
                            cookie,
                            "Adicione a flag Secure ao cookie para restringir o envio apenas via HTTPS."));
                }
                if (!lower.contains("httponly")) {
                    achados.add(new Finding(
                            "Cookie '" + nomeCookie + "' sem flag HttpOnly",
                            Severity.MEDIA, baseUrl,
                            "O cookie pode ser lido via JavaScript (document.cookie), facilitando roubo via XSS.",
                            cookie,
                            "Adicione a flag HttpOnly para impedir acesso via JavaScript no navegador."));
                }
                if (!lower.contains("samesite")) {
                    achados.add(new Finding(
                            "Cookie '" + nomeCookie + "' sem atributo SameSite",
                            Severity.BAIXA, baseUrl,
                            "Sem SameSite, o cookie pode ser enviado em requisições cross-site, favorecendo CSRF.",
                            cookie,
                            "Defina SameSite=Lax ou Strict conforme a necessidade da aplicação."));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro no check de cookies: " + e.getMessage());
        }
        return achados;
    }
}
