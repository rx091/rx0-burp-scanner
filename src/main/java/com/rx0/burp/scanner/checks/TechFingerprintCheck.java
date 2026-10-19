package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Identifica a tecnologia/CMS/framework do alvo via assinaturas em headers,
 * cookies e marcadores no HTML. Não é uma falha em si — é um achado
 * INFORMATIVO que ajuda a direcionar o resto do teste manual (ex: se é
 * WordPress, vale rodar wpscan; se é Laravel, checar debug mode exposto).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class TechFingerprintCheck implements VulnCheck {

    private static final Map<String, Pattern> ASSINATURAS_HTML = new LinkedHashMap<>();
    static {
        ASSINATURAS_HTML.put("WordPress", Pattern.compile("wp-content|wp-includes|/wp-json/", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_HTML.put("Joomla", Pattern.compile("Joomla!|/media/jui/", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_HTML.put("Drupal", Pattern.compile("Drupal\\.settings|/sites/default/files", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_HTML.put("Laravel", Pattern.compile("laravel_session|XSRF-TOKEN", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_HTML.put("Django", Pattern.compile("csrfmiddlewaretoken", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_HTML.put("Ruby on Rails", Pattern.compile("authenticity_token|data-turbo", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_HTML.put("ASP.NET", Pattern.compile("__VIEWSTATE|__EVENTVALIDATION", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_HTML.put("React", Pattern.compile("__NEXT_DATA__|data-reactroot|react-dom", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_HTML.put("Angular", Pattern.compile("ng-version|ng-app", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_HTML.put("Vue.js", Pattern.compile("data-v-[a-f0-9]{6,}|__VUE__", Pattern.CASE_INSENSITIVE));
    }

    private static final Map<String, Pattern> ASSINATURAS_COOKIE = new LinkedHashMap<>();
    static {
        ASSINATURAS_COOKIE.put("PHP", Pattern.compile("PHPSESSID", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_COOKIE.put("Java (JSESSIONID)", Pattern.compile("JSESSIONID", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_COOKIE.put("ASP.NET", Pattern.compile("ASP\\.NET_SessionId", Pattern.CASE_INSENSITIVE));
        ASSINATURAS_COOKIE.put("Express/Node.js", Pattern.compile("connect\\.sid", Pattern.CASE_INSENSITIVE));
    }

    @Override
    public String nome() {
        return "Fingerprint de tecnologia (CMS/framework)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        try {
            HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(baseUrl)).response();
            if (resp == null) return achados;

            List<String> detectados = new ArrayList<>();
            String body = resp.bodyToString();
            if (body != null) {
                for (Map.Entry<String, Pattern> entry : ASSINATURAS_HTML.entrySet()) {
                    if (entry.getValue().matcher(body).find()) detectados.add(entry.getKey());
                }
            }

            StringBuilder cookiesVistos = new StringBuilder();
            for (HttpHeader h : resp.headers()) {
                if (!h.name().equalsIgnoreCase("Set-Cookie")) continue;
                cookiesVistos.append(h.value()).append(" ");
            }
            for (Map.Entry<String, Pattern> entry : ASSINATURAS_COOKIE.entrySet()) {
                if (entry.getValue().matcher(cookiesVistos).find()) detectados.add(entry.getKey());
            }

            // Server/X-Powered-By já são reportados pelo SecurityHeadersCheck, mas aqui agregamos no fingerprint
            String servidor = null, poweredBy = null;
            for (HttpHeader h : resp.headers()) {
                if (h.name().equalsIgnoreCase("Server")) servidor = h.value();
                if (h.name().equalsIgnoreCase("X-Powered-By")) poweredBy = h.value();
            }

            if (!detectados.isEmpty() || servidor != null || poweredBy != null) {
                StringBuilder resumo = new StringBuilder();
                if (!detectados.isEmpty()) resumo.append("Tecnologias detectadas: ").append(String.join(", ", detectados)).append(". ");
                if (servidor != null) resumo.append("Server: ").append(servidor).append(". ");
                if (poweredBy != null) resumo.append("X-Powered-By: ").append(poweredBy).append(".");

                achados.add(new Finding(
                        "Fingerprint de tecnologia do alvo",
                        Severity.INFO,
                        baseUrl,
                        "Identificação da stack tecnológica do alvo, útil para direcionar testes manuais complementares " +
                                "(ex: WordPress → rodar wpscan; Laravel → checar debug mode/.env exposto; ASP.NET → revisar ViewState).",
                        resumo.toString().trim(),
                        "Considere ocultar headers de versão (Server, X-Powered-By) pra dificultar reconhecimento automatizado, " +
                                "embora isso seja apenas 'security through obscurity' — mantenha o software sempre atualizado."));
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro no check de fingerprint: " + e.getMessage());
        }
        return achados;
    }
}
