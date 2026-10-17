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
 * Check ESTÁTICO (não executa JS de verdade): baixa a página inicial e
 * procura por padrões de código onde uma FONTE controlável pelo atacante
 * (location.hash, location.search, document.URL, window.name...) alimenta
 * diretamente um SINK perigoso (innerHTML, document.write, eval,
 * insertAdjacentHTML...) no mesmo trecho de JavaScript — um padrão clássico
 * de DOM-based XSS.
 *
 * Isso é só um SINAL para investigação manual (ex: abrir no DevTools e
 * testar `#<img src=x onerror=alert(1)>` na URL) — não confirma exploração.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class DomXssCheck implements VulnCheck {

    private static final Pattern[] SINKS = {
            Pattern.compile("\\.innerHTML\\s*="),
            Pattern.compile("\\.outerHTML\\s*="),
            Pattern.compile("document\\.write\\s*\\("),
            Pattern.compile("document\\.writeln\\s*\\("),
            Pattern.compile("\\.insertAdjacentHTML\\s*\\("),
            Pattern.compile("\\beval\\s*\\("),
            Pattern.compile("setTimeout\\s*\\(\\s*[\"']"),
            Pattern.compile("\\$\\([^)]*\\)\\.html\\s*\\("), // jQuery .html()
    };

    private static final Pattern[] FONTES_CONTROLAVEIS = {
            Pattern.compile("location\\.hash"),
            Pattern.compile("location\\.search"),
            Pattern.compile("location\\.href"),
            Pattern.compile("document\\.URL"),
            Pattern.compile("document\\.referrer"),
            Pattern.compile("window\\.name"),
            Pattern.compile("URLSearchParams"),
    };

    private static final int JANELA_DE_PROXIMIDADE = 150; // caracteres de distância considerados "mesmo trecho"

    @Override
    public String nome() {
        return "DOM-based XSS (análise estática de source/sink)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) return achados;

            String body = resp.bodyToString();
            if (body == null || body.isBlank()) return achados;

            // Mapa achado -> posição, pra evitar reportar o mesmo par source+sink várias vezes
            Map<String, Integer> ocorrenciasReportadas = new LinkedHashMap<>();

            for (Pattern sinkPattern : SINKS) {
                Matcher sinkMatcher = sinkPattern.matcher(body);
                while (sinkMatcher.find()) {
                    int inicioJanela = Math.max(0, sinkMatcher.start() - JANELA_DE_PROXIMIDADE);
                    int fimJanela = Math.min(body.length(), sinkMatcher.end() + JANELA_DE_PROXIMIDADE);
                    String trecho = body.substring(inicioJanela, fimJanela);

                    for (Pattern fontePattern : FONTES_CONTROLAVEIS) {
                        Matcher fonteMatcher = fontePattern.matcher(trecho);
                        if (fonteMatcher.find()) {
                            String chave = sinkPattern.pattern() + "|" + fontePattern.pattern();
                            if (ocorrenciasReportadas.containsKey(chave)) continue;
                            ocorrenciasReportadas.put(chave, sinkMatcher.start());

                            achados.add(new Finding(
                                    "Possível DOM-based XSS: fonte controlável próxima de sink perigoso",
                                    Severity.MEDIA,
                                    baseUrl,
                                    "No JavaScript da página foi encontrada uma fonte controlável pelo atacante ('" + fonteMatcher.pattern()
                                            + "') a poucos caracteres de distância de um sink perigoso ('" + sinkPattern.pattern()
                                            + "'). Isso é um padrão comum de DOM-based XSS, onde dados da própria URL são escritos " +
                                            "diretamente no DOM sem sanitização. Requer confirmação manual no navegador (DevTools).",
                                    "Trecho (resumido): " + resumir(trecho.trim(), 200),
                                    "Nunca escreva fontes controláveis pelo usuário (location.hash, location.search, etc) diretamente " +
                                            "em sinks de HTML/execução. Use textContent em vez de innerHTML, e sanitize com uma biblioteca " +
                                            "como DOMPurify quando HTML dinâmico for realmente necessário."));
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro no check de DOM XSS: " + e.getMessage());
        }
        return achados;
    }

    private String resumir(String texto, int max) {
        if (texto.length() <= max) return texto;
        return texto.substring(0, max) + "...";
    }
}
