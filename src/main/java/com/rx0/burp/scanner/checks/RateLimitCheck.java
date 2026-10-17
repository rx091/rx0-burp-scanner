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
 * Dispara uma rajada de requisições para endpoints de login/API comuns e
 * verifica se o servidor aplica algum tipo de rate limiting (HTTP 429, ou
 * bloqueio progressivo). Ausência disso facilita brute-force de credenciais
 * e abuso de API (API4:2023 Unrestricted Resource Consumption).
 *
 * O volume é propositalmente baixo (12 requisições) para não gerar carga
 * excessiva — ajuste RAJADA se quiser um teste mais agressivo.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class RateLimitCheck implements VulnCheck {

    private static final String[] PATHS = {"/api/login", "/api/v1/login", "/api/auth/login", "/login"};
    private static final int RAJADA = 12;

    @Override
    public String nome() {
        return "Rate limiting em endpoints de login/API";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                String corpo = "{\"username\":\"rx0_test_user\",\"password\":\"senha_invalida_" + System.currentTimeMillis() + "\"}";

                int sucessosSemBloqueio = 0;
                boolean algumaResposta = false;

                for (int i = 0; i < RAJADA; i++) {
                    HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                            .withMethod("POST")
                            .withAddedHeader("Content-Type", "application/json")
                            .withBody(corpo);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;
                    algumaResposta = true;

                    int status = resp.statusCode();
                    if (status == 429 || status == 403) {
                        sucessosSemBloqueio = -1; // encontrou bloqueio, interrompe a rajada
                        break;
                    }
                    // considera "sem bloqueio" qualquer resposta normal (200/400/401) que não seja rate-limit
                    sucessosSemBloqueio++;
                }

                if (algumaResposta && sucessosSemBloqueio >= RAJADA) {
                    achados.add(new Finding(
                            "Possível ausência de rate limiting em " + path,
                            Severity.MEDIA,
                            url,
                            "Foram enviadas " + RAJADA + " tentativas de login seguidas sem que o servidor retornasse " +
                                    "HTTP 429 (Too Many Requests) ou 403 em nenhum momento. Isso pode facilitar ataques de " +
                                    "força bruta e credential stuffing.",
                            RAJADA + " requisições enviadas, nenhuma bloqueada.",
                            "Implemente rate limiting (por IP e/ou por conta) e considere CAPTCHA ou bloqueio progressivo após tentativas falhas."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de rate limit (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }
}
