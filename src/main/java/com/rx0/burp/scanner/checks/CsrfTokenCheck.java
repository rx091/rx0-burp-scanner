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
 * Análise ESTÁTICA: busca formulários <form method="post"> na página
 * inicial (e em paths comuns de login/cadastro) e verifica se existe algum
 * campo hidden com nome que sugira token anti-CSRF (csrf, token, authenticity,
 * nonce...). Formulários POST sem nenhum campo desse tipo são um indício de
 * ausência de proteção CSRF — requer confirmação manual (alguns frameworks
 * usam cookie SameSite ou header customizado em vez de campo hidden).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class CsrfTokenCheck implements VulnCheck {

    private static final String[] PATHS = {"/", "/login", "/signup", "/register", "/contact", "/comment"};

    private static final Pattern PADRAO_FORM_POST = Pattern.compile(
            "<form\\b[^>]*method=[\"']?post[\"']?[^>]*>(.*?)</form>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private static final Pattern PADRAO_CAMPO_TOKEN = Pattern.compile(
            "<input[^>]*name=[\"']?(csrf|_csrf|csrf_token|authenticity_token|_token|nonce|xsrf|anti[-_]?forgery)[^\"'>]*[\"']?",
            Pattern.CASE_INSENSITIVE);

    @Override
    public String nome() {
        return "CSRF — formulários sem token anti-CSRF";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response();
                if (resp == null || resp.statusCode() != 200) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                Matcher formMatcher = PADRAO_FORM_POST.matcher(body);
                int indiceForm = 0;
                while (formMatcher.find()) {
                    indiceForm++;
                    String conteudoForm = formMatcher.group(1);
                    boolean temToken = PADRAO_CAMPO_TOKEN.matcher(conteudoForm).find();

                    if (!temToken) {
                        achados.add(new Finding(
                                "Formulário POST sem token anti-CSRF aparente (form #" + indiceForm + ") em " + path,
                                Severity.MEDIA,
                                url,
                                "Um formulário com method=\"post\" foi encontrado sem nenhum campo hidden com nome típico de " +
                                        "token anti-CSRF (csrf, _token, authenticity_token...). Isso PODE ser uma falha de CSRF — mas " +
                                        "também pode ser proteção via cookie SameSite, header customizado (ex: X-CSRF-Token via JS) " +
                                        "ou Double Submit Cookie, que não aparecem na análise estática do HTML. Requer confirmação manual.",
                                "Trecho do formulário (resumido): " + resumir(conteudoForm.trim(), 150),
                                "Implemente proteção CSRF (token sincronizador, SameSite=Strict/Lax nos cookies de sessão, " +
                                        "ou verificação de header customizado) em toda ação que altera estado (POST/PUT/DELETE)."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de CSRF (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }

    private String resumir(String texto, int max) {
        if (texto.length() <= max) return texto;
        return texto.substring(0, max) + "...";
    }
}
