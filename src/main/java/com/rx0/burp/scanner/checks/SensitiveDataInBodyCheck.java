package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Varre o corpo da página inicial (e de alguns paths comuns) em busca de
 * dados sensíveis vazando diretamente no HTML/JS/JSON servido: chave
 * privada, e-mails em massa, endereços IP privados, números de cartão de
 * crédito e CPF/SSN em texto puro.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class SensitiveDataInBodyCheck implements VulnCheck {

    private static final String[] PATHS = {"/", "/sitemap.xml", "/about", "/contact", "/humans.txt"};

    private static final Map<String, Pattern> ASSINATURAS = new LinkedHashMap<>();
    static {
        ASSINATURAS.put("Chave privada exposta",
                Pattern.compile("-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"));
        ASSINATURAS.put("JSON Web Key (JWK) privado exposto",
                Pattern.compile("\"kty\"\\s*:\\s*\"(RSA|EC)\".{0,400}\"d\"\\s*:\\s*\"", Pattern.DOTALL));
        ASSINATURAS.put("Endereço IP privado exposto",
                Pattern.compile("\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b"));
        ASSINATURAS.put("Possível número de cartão de crédito exposto",
                Pattern.compile("\\b(?:\\d[ -]*?){13,16}\\b"));
        ASSINATURAS.put("Possível CPF/SSN exposto",
                Pattern.compile("\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b|\\b\\d{3}-\\d{2}-\\d{4}\\b"));
        ASSINATURAS.put("Connection string de banco de dados exposta",
                Pattern.compile("(jdbc:|mongodb(\\+srv)?://|Server=.+;Database=|Data Source=.+;)", Pattern.CASE_INSENSITIVE));
    }

    // Limite de e-mails distintos pra considerar "vazamento em massa" (evita flagar 1 e-mail de contato legítimo)
    private static final int LIMIAR_EMAILS = 5;
    private static final Pattern PADRAO_EMAIL = Pattern.compile("[\\w.+-]+@[\\w-]+\\.[\\w.-]+");

    @Override
    public String nome() {
        return "Dados sensíveis vazando no corpo da resposta";
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
                if (body == null || body.isBlank()) continue;

                for (Map.Entry<String, Pattern> entry : ASSINATURAS.entrySet()) {
                    Matcher m = entry.getValue().matcher(body);
                    if (m.find()) {
                        boolean sensivel = entry.getKey().contains("Chave privada") || entry.getKey().contains("JWK")
                                || entry.getKey().contains("Connection string");
                        achados.add(new Finding(
                                entry.getKey() + " em " + path,
                                sensivel ? Severity.CRITICA : Severity.MEDIA,
                                url,
                                "Foi encontrado um padrão de '" + entry.getKey().toLowerCase() + "' diretamente no corpo da resposta. " +
                                        "Confirme manualmente a veracidade (alguns padrões como cartão/CPF podem ter falsos-positivos — " +
                                        "números que coincidem com o formato mas não são dados reais).",
                                "Trecho correspondente: " + resumir(mascarar(m.group()), 100),
                                sensivel
                                        ? "Remova imediatamente esse dado do código/resposta pública e rotacione a credencial/chave se for real."
                                        : "Evite expor esse tipo de dado em respostas públicas; se for intencional (ex: página de contato), ignore este achado."));
                    }
                }

                // E-mails em massa (separado, pois usa contagem em vez de find() simples)
                Matcher emailMatcher = PADRAO_EMAIL.matcher(body);
                int contagemEmails = 0;
                while (emailMatcher.find()) contagemEmails++;
                if (contagemEmails >= LIMIAR_EMAILS) {
                    achados.add(new Finding(
                            "Possível vazamento em massa de e-mails em " + path,
                            Severity.MEDIA,
                            url,
                            "Foram encontrados " + contagemEmails + " endereços de e-mail distintos no corpo da resposta. " +
                                    "Isso pode ser uma lista de usuários/contatos exposta indevidamente (diferente de 1-2 e-mails " +
                                    "de contato legítimos em uma página institucional).",
                            "Quantidade de e-mails encontrados: " + contagemEmails,
                            "Revise se essa quantidade de e-mails deveria estar pública; se for uma listagem de usuários, restrinja o acesso."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de dados sensíveis no corpo (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }

    private String mascarar(String texto) {
        if (texto.length() <= 8) return texto;
        return texto.substring(0, 4) + "****" + texto.substring(texto.length() - 4);
    }

    private String resumir(String texto, int max) {
        if (texto.length() <= max) return texto;
        return texto.substring(0, max) + "...";
    }
}
