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
 * Envia um Origin forjado e verifica se o servidor reflete esse Origin
 * em Access-Control-Allow-Origin, especialmente junto de credentials=true.
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class CorsMisconfigCheck implements VulnCheck {

    private static final String ORIGEM_FORJADA = "https://rx0-cors-test.evil.example";

    @Override
    public String nome() {
        return "Configuração de CORS";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl)
                    .withAddedHeader("Origin", ORIGEM_FORJADA);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return achados;

            Optional<HttpHeader> allowOrigin = resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Access-Control-Allow-Origin"))
                    .findFirst();
            Optional<HttpHeader> allowCreds = resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Access-Control-Allow-Credentials"))
                    .findFirst();

            if (allowOrigin.isPresent()) {
                String valor = allowOrigin.get().value();
                boolean reflete = valor.equals(ORIGEM_FORJADA);
                boolean credenciais = allowCreds.isPresent() && allowCreds.get().value().equalsIgnoreCase("true");

                if (reflete && credenciais) {
                    achados.add(new Finding(
                            "CORS mal configurado: Origin refletido com credentials=true",
                            Severity.CRITICA, baseUrl,
                            "O servidor reflete qualquer Origin enviado e permite credentials, permitindo que um site malicioso leia respostas autenticadas da vítima.",
                            "Origin enviado: " + ORIGEM_FORJADA + " | Access-Control-Allow-Origin: " + valor
                                    + " | Access-Control-Allow-Credentials: true",
                            "Nunca reflita o Origin dinamicamente junto de credentials=true. Use uma allowlist fixa de origens confiáveis."));
                } else if (reflete) {
                    achados.add(new Finding(
                            "CORS reflete Origin arbitrário",
                            Severity.MEDIA, baseUrl,
                            "O servidor aceita e reflete qualquer Origin em Access-Control-Allow-Origin.",
                            "Origin enviado: " + ORIGEM_FORJADA + " | Access-Control-Allow-Origin: " + valor,
                            "Restrinja Access-Control-Allow-Origin a uma lista de origens confiáveis."));
                } else if (valor.equals("*") && credenciais) {
                    achados.add(new Finding(
                            "CORS com wildcard (*) e credentials=true",
                            Severity.ALTA, baseUrl,
                            "Essa combinação é inválida por spec, mas quando ocorre indica configuração perigosa.",
                            "Access-Control-Allow-Origin: * | Allow-Credentials: true",
                            "Use uma origem explícita (nunca *) quando credentials estiver habilitado."));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro no check de CORS: " + e.getMessage());
        }
        return achados;
    }
}
