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
 * Dois checks estáticos relacionados a formulários legados/ASP.NET:
 *  - ASP.NET ViewState presente SEM __VIEWSTATEMAC — permite adulteração do
 *    ViewState (pode levar a deserialização insegura, dependendo da versão).
 *  - Campo <input type="password"> sem autocomplete="off"/"new-password" —
 *    o navegador pode guardar a senha em caches/autofill de forma insegura
 *    em dispositivos compartilhados.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class ViewStateAndAutocompleteCheck implements VulnCheck {

    private static final String[] PATHS = {"/", "/login", "/signin", "/account/login"};

    private static final Pattern PADRAO_VIEWSTATE = Pattern.compile("name=[\"']__VIEWSTATE[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern PADRAO_VIEWSTATEMAC = Pattern.compile("name=[\"']__VIEWSTATEMAC[\"']", Pattern.CASE_INSENSITIVE);

    private static final Pattern PADRAO_CAMPO_SENHA = Pattern.compile("<input\\b[^>]*type=[\"']password[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern PADRAO_AUTOCOMPLETE_OFF = Pattern.compile("autocomplete=[\"'](off|new-password)[\"']", Pattern.CASE_INSENSITIVE);

    @Override
    public String nome() {
        return "ASP.NET ViewState sem MAC / autocomplete em senha";
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

                // --- ViewState sem MAC ---
                if (PADRAO_VIEWSTATE.matcher(body).find() && !PADRAO_VIEWSTATEMAC.matcher(body).find()) {
                    achados.add(new Finding(
                            "ASP.NET ViewState sem MAC habilitado",
                            Severity.ALTA,
                            url,
                            "A página usa __VIEWSTATE (ASP.NET Web Forms) mas não possui __VIEWSTATEMAC. Sem o MAC, o ViewState " +
                                    "pode ser adulterado pelo cliente sem detecção, e dependendo da versão do .NET pode abrir caminho " +
                                    "para deserialização insegura (ViewState deserialization RCE).",
                            "__VIEWSTATE encontrado, __VIEWSTATEMAC ausente.",
                            "Habilite EnableViewStateMac=true (é o padrão em versões recentes do .NET, confirme que não foi desabilitado) " +
                                    "e mantenha o framework atualizado."));
                }

                // --- Autocomplete em campo de senha ---
                Matcher campoSenhaMatcher = PADRAO_CAMPO_SENHA.matcher(body);
                int indice = 0;
                while (campoSenhaMatcher.find()) {
                    indice++;
                    String tagCompleta = campoSenhaMatcher.group();
                    if (!PADRAO_AUTOCOMPLETE_OFF.matcher(tagCompleta).find()) {
                        achados.add(new Finding(
                                "Campo de senha sem autocomplete=\"off\"/\"new-password\" (campo #" + indice + ") em " + path,
                                Severity.BAIXA,
                                url,
                                "O campo de senha não desabilita o autocomplete do navegador. Em dispositivos compartilhados/públicos, " +
                                        "isso pode permitir que a senha fique salva no autofill do navegador.",
                                "Tag encontrada: " + resumir(tagCompleta, 120),
                                "Adicione autocomplete=\"new-password\" (recomendado atualmente pelos navegadores) ao campo de senha."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de ViewState/autocomplete (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }

    private String resumir(String texto, int max) {
        if (texto.length() <= max) return texto;
        return texto.substring(0, max) + "...";
    }
}
