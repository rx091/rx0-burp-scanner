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
 * Envia, em endpoints típicos de cadastro/atualização de perfil, campos
 * EXTRAS que um usuário comum nunca deveria poder setar (isAdmin, role,
 * verified, balance, is_staff...) e verifica se a resposta ECOA esses
 * campos com o valor privilegiado que enviamos — indício de Mass
 * Assignment (API6:2023 Unrestricted Access to Sensitive Business Flows /
 * API3:2023 Broken Object Property Level Authorization).
 *
 * É um sinal, não uma confirmação definitiva: sempre valide manualmente se
 * o campo realmente foi persistido (ex: deslogando e logando de novo, ou
 * consultando o recurso em uma segunda requisição).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class MassAssignmentCheck implements VulnCheck {

    private static final String[] PATHS = {
            "/api/register", "/api/v1/register", "/api/users", "/api/signup",
            "/api/profile", "/api/me", "/api/account"
    };

    // nome do campo privilegiado -> valor que tentamos injetar
    private static final String[][] CAMPOS_PRIVILEGIADOS = {
            {"isAdmin", "true"},
            {"is_admin", "true"},
            {"role", "\"admin\""},
            {"is_staff", "true"},
            {"verified", "true"},
            {"email_verified", "true"},
            {"balance", "999999"},
            {"credits", "999999"},
            {"plan", "\"enterprise\""},
    };

    @Override
    public String nome() {
        return "Mass Assignment (campos privilegiados em cadastro/perfil)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String path : PATHS) {
            try {
                String url = base + path;
                String usuarioTeste = "rx0_mass_assign_" + (System.currentTimeMillis() % 1000000);

                StringBuilder corpo = new StringBuilder("{");
                corpo.append("\"username\":\"").append(usuarioTeste).append("\",");
                corpo.append("\"email\":\"").append(usuarioTeste).append("@rx0-test.invalid\",");
                corpo.append("\"password\":\"SenhaTeste123!\",");
                for (int i = 0; i < CAMPOS_PRIVILEGIADOS.length; i++) {
                    corpo.append("\"").append(CAMPOS_PRIVILEGIADOS[i][0]).append("\":").append(CAMPOS_PRIVILEGIADOS[i][1]);
                    if (i < CAMPOS_PRIVILEGIADOS.length - 1) corpo.append(",");
                }
                corpo.append("}");

                HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/json")
                        .withBody(corpo.toString());
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String respBody = resp.bodyToString();
                if (respBody == null || resp.statusCode() >= 400) continue;

                for (String[] campo : CAMPOS_PRIVILEGIADOS) {
                    String nomeCampo = campo[0];
                    String valorEsperado = campo[1].replace("\"", "");
                    Pattern p = Pattern.compile("\"" + Pattern.quote(nomeCampo) + "\"\\s*:\\s*\"?" + Pattern.quote(valorEsperado) + "\"?",
                            Pattern.CASE_INSENSITIVE);
                    if (p.matcher(respBody).find()) {
                        achados.add(new Finding(
                                "Possível Mass Assignment: campo '" + nomeCampo + "' aceito em " + path,
                                Severity.ALTA,
                                url,
                                "Enviamos o campo privilegiado '" + nomeCampo + "' com valor '" + valorEsperado + "' junto do cadastro, " +
                                        "e a resposta ecoou esse mesmo valor de volta — sinal de que o backend está atribuindo campos do " +
                                        "JSON diretamente ao modelo/entidade sem uma allowlist explícita de campos permitidos.",
                                "Campo testado: " + nomeCampo + "=" + valorEsperado + " | Confirme manualmente se foi persistido de fato.",
                                "Nunca faça bind direto do JSON recebido para a entidade do banco. Use DTOs de entrada explícitos " +
                                        "(allowlist de campos) e nunca aceite alteração de campos sensíveis (role, isAdmin, balance) via endpoint público.",
                                "1) Repita o cadastro com o usuário '" + usuarioTeste + "' e, em seguida, tente LOGAR com essas credenciais " +
                                        "(username: " + usuarioTeste + " / senha: SenhaTeste123!). 2) Uma vez logado, acesse funcionalidades " +
                                        "restritas a admin (painel administrativo, endpoints /api/admin/*) pra confirmar se o campo '" + nomeCampo +
                                        "' realmente elevou o privilégio. 3) Isso demonstra escalação de privilégio completa a partir de um cadastro público."));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de Mass Assignment (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }
}
