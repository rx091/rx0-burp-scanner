package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Busca em respostas de endpoints de API comuns por CAMPOS JSON que sugerem
 * exposição excessiva de dados sensíveis (API3:2023 Broken Object Property
 * Level Authorization / Excessive Data Exposure): senha em texto, hash,
 * tokens, segredos, chaves de API, CPF/CNPJ, cartão de crédito.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class ExcessiveDataExposureCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/users", "/api/v1/users", "/api/user/me", "/api/me", "/api/profile",
            "/api/accounts", "/api/customers"
    };

    private static final Pattern[] CAMPOS_SENSIVEIS = {
            Pattern.compile("\"password\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"senha\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"password_hash\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(api_key|apikey|api_secret)\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"secret\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(access_token|refresh_token)\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(cpf|cnpj)\"\\s*:\\s*\"?\\d", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(credit_card|card_number|cc_number)\"\\s*:\\s*\"?\\d", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"ssn\"\\s*:\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String nome() {
        return "Exposição excessiva de dados em respostas de API";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url).withAddedHeader("Accept", "application/json");
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null || resp.statusCode() != 200) continue;

                String body = resp.bodyToString();
                if (body == null || body.isBlank()) continue;

                for (Pattern p : CAMPOS_SENSIVEIS) {
                    Matcher m = p.matcher(body);
                    if (m.find()) {
                        achados.add(new Finding(
                                "Possível exposição excessiva de dados em " + path,
                                Severity.ALTA,
                                url,
                                "A resposta da API contém um campo que parece ser um dado sensível retornado sem necessidade " +
                                        "(senha, token, segredo ou documento pessoal). Isso é um padrão clássico de Excessive Data Exposure " +
                                        "(API3:2023 do OWASP API Security Top 10).",
                                "Trecho correspondente: " + resumir(m.group(), 120),
                                "Filtre a resposta da API para retornar apenas os campos que o cliente realmente precisa (use DTOs/serializers explícitos, nunca serialize a entidade inteira)."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de exposição de dados (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }

    private String resumir(String texto, int max) {
        if (texto.length() <= max) return texto;
        return texto.substring(0, max) + "...";
    }
}
