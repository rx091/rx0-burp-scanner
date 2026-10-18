package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * LDAP Injection e XPath Injection — ambos detectados via assinaturas de
 * ERRO expostas quando o parser/query engine recebe um caractere especial
 * inesperado (abordagem igual ao SqlErrorCheck, mas para esses dois tipos
 * de injeção). Payloads enviados em parâmetros típicos de login/busca.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class LdapXpathInjectionCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"username", "user", "login", "uid", "search", "filter", "q"};

    private static final String[] PAYLOADS_LDAP = {"*)(uid=*))(|(uid=*", "*)(|(password=*))", "admin*)((|userPassword=*)"};
    private static final String[] PAYLOADS_XPATH = {"' or '1'='1", "'] | //*[contains(*,'", "x' or 1=1 or 'x'='y"};

    private static final Pattern[] ASSINATURAS_LDAP = {
            Pattern.compile("LDAPException", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javax\\.naming\\.directory", Pattern.CASE_INSENSITIVE),
            Pattern.compile("com\\.sun\\.jndi\\.ldap", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Invalid DN syntax", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Bad search filter", Pattern.CASE_INSENSITIVE),
    };

    private static final Pattern[] ASSINATURAS_XPATH = {
            Pattern.compile("XPathException", Pattern.CASE_INSENSITIVE),
            Pattern.compile("com\\.sun\\.org\\.apache\\.xpath", Pattern.CASE_INSENSITIVE),
            Pattern.compile("MS\\.Internal\\.Xml\\.XPath", Pattern.CASE_INSENSITIVE),
            Pattern.compile("XPathEvalError", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Invalid expression|Invalid XPath", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String nome() {
        return "LDAP Injection / XPath Injection (error-based)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            achados.addAll(testar(api, base, param, PAYLOADS_LDAP, ASSINATURAS_LDAP, "LDAP Injection"));
            achados.addAll(testar(api, base, param, PAYLOADS_XPATH, ASSINATURAS_XPATH, "XPath Injection"));
        }
        return achados;
    }

    private List<Finding> testar(MontoyaApi api, String base, String param, String[] payloads,
                                  Pattern[] assinaturas, String tipo) {
        List<Finding> achados = new ArrayList<>();
        for (String payload : payloads) {
            try {
                String url = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                for (Pattern p : assinaturas) {
                    if (p.matcher(body).find()) {
                        achados.add(new Finding(
                                "Possível " + tipo + " no parâmetro '" + param + "'",
                                Severity.CRITICA,
                                url,
                                "O envio de um payload de " + tipo + " causou um erro característico exposto na resposta, " +
                                        "indicando que a entrada é usada diretamente em uma consulta " +
                                        (tipo.equals("LDAP Injection") ? "LDAP" : "XPath") + " sem sanitização.",
                                "Payload: " + payload + " | Assinatura detectada: " + p.pattern(),
                                tipo.equals("LDAP Injection")
                                        ? "Use APIs de LDAP com parâmetros vinculados (bind) em vez de concatenar strings no filtro de busca, e escape caracteres especiais LDAP (*, (, ), \\, NUL)."
                                        : "Use consultas XPath parametrizadas (XPathExpression com variáveis) em vez de concatenar entrada do usuário na expressão.",
                                tipo.equals("LDAP Injection")
                                        ? "1) No Repeater, teste bypass de autenticação com payload tipo *)(uid=*))(|(uid=* no campo de " +
                                          "usuário de um formulário de login LDAP. 2) Se autenticar sem senha válida, é bypass completo. " +
                                          "3) Para extração de dados, use blind LDAP injection testando filtros booleanos incrementais."
                                        : "1) Teste bypass de login com payload ' or '1'='1 no campo de usuário de um login que use XML/XPath " +
                                          "como fonte de dados. 2) Para extração blind, use payloads que testam caractere por caractere " +
                                          "(ex: substring(name,1,1)='a') e observe diferença de comportamento."));
                        return achados; // já confirmado nesse param+tipo
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de " + tipo + " (param " + param + "): " + e.getMessage());
            }
        }
        return achados;
    }
}
