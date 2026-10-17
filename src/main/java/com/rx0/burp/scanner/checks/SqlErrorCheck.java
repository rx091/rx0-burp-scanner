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
 * Envia um caractere de aspa simples em parâmetros comuns e procura por
 * assinaturas de erro de banco de dados na resposta (SQLi error-based).
 * Probe leve, não executa exploração — apenas detecção de erro verboso.
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class SqlErrorCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"id", "user", "product", "category", "page", "item"};
    private static final String[] PAYLOADS = {"'", "\"", "1'\"", "') OR ('1'='1"};

    private static final Pattern[] ASSINATURAS_ERRO = {
            Pattern.compile("SQL syntax.*MySQL", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Warning.*mysqli?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("PostgreSQL.*ERROR", Pattern.CASE_INSENSITIVE),
            Pattern.compile("ORA-\\d{5}"),
            Pattern.compile("Microsoft OLE DB Provider for SQL Server"),
            Pattern.compile("Unclosed quotation mark after the character string"),
            Pattern.compile("SQLite3?::", Pattern.CASE_INSENSITIVE),
            Pattern.compile("System\\.Data\\.SqlClient"),
            Pattern.compile("PDOException", Pattern.CASE_INSENSITIVE)
    };

    @Override
    public String nome() {
        return "Erros de SQL expostos (probe leve)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            for (String payload : PAYLOADS) {
                try {
                    String testUrl = base + "/?" + param + "=" + java.net.URLEncoder.encode(payload, "UTF-8");
                    HttpRequest req = HttpRequest.httpRequestFromUrl(testUrl);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body == null) continue;

                    for (Pattern p : ASSINATURAS_ERRO) {
                        if (p.matcher(body).find()) {
                            achados.add(new Finding(
                                    "Possível SQL Injection (erro exposto) no parâmetro '" + param + "'",
                                    Severity.CRITICA,
                                    testUrl,
                                    "O envio de um payload com caractere especial causou um erro de banco de dados visível na resposta, indicando que a entrada não é sanitizada antes da query.",
                                    "Payload: " + payload + " | Assinatura detectada: " + p.pattern(),
                                    "Use prepared statements / queries parametrizadas em toda a aplicação e desative mensagens de erro verbosas em produção."));
                            // já achou assinatura pra esse param+payload, não precisa testar as outras assinaturas
                            break;
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro no check de SQLi (param " + param + "): " + e.getMessage());
                }
            }
        }
        return achados;
    }
}
