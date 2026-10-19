package com.rx0.burp.scanner.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;
import com.rx0.burp.scanner.VulnCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Testa headers "unkeyed" (que não entram na chave do cache mas podem afetar
 * o CONTEÚDO da resposta) — se o servidor reflete o valor desses headers no
 * corpo/resposta E existe cache na frente (CDN/proxy reverso), um único
 * request malicioso pode "envenenar" a resposta cacheada para TODOS os
 * visitantes seguintes.
 *
 * Esse check detecta a CONDIÇÃO (reflexão de header unkeyed + presença de
 * cache) — confirmar o envenenamento de fato requer um segundo request sem
 * o header malicioso pra ver se o conteúdo malicioso "grudou" no cache, o
 * que é mais arriscado de automatizar (pode afetar visitantes reais) e por
 * isso fica como passo de validação manual.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class WebCachePoisoningCheck implements VulnCheck {

    private static final String MARCADOR = "rx0cachetest" + (System.currentTimeMillis() % 100000);

    private static final String[] HEADERS_UNKEYED = {
            "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
            "X-Original-URL", "X-Rewrite-URL", "X-Host"
    };

    @Override
    public String nome() {
        return "Web Cache Poisoning (headers unkeyed)";
    }

    @Override
    public List<Finding> executar(MontoyaApi api, String baseUrl) {
        List<Finding> achados = new ArrayList<>();

        // Primeiro, detecta se há cache na frente (Cache-Control ou headers de CDN)
        boolean temCache = detectarCache(api, baseUrl);

        for (String header : HEADERS_UNKEYED) {
            try {
                String valorMarcado = header.toLowerCase().contains("scheme") || header.toLowerCase().contains("proto")
                        ? "rx0" + MARCADOR : MARCADOR + ".evil-rx0.test";

                HttpRequest req = HttpRequest.httpRequestFromUrl(baseUrl)
                        .withAddedHeader(header, valorMarcado);
                HttpResponse resp = api.http().sendRequest(req).response();
                if (resp == null) continue;

                String body = resp.bodyToString();
                boolean refletido = body != null && body.contains(valorMarcado);

                if (refletido) {
                    achados.add(new Finding(
                            "Possível Web Cache Poisoning via header '" + header + "'" + (temCache ? " (cache detectado)" : ""),
                            temCache ? Severity.ALTA : Severity.MEDIA,
                            baseUrl,
                            "O header '" + header + "' (que normalmente NÃO faz parte da chave de cache de CDNs/proxies) foi " +
                                    "refletido no corpo da resposta. " + (temCache
                                    ? "Como há indícios de cache na frente deste alvo, isso é uma condição real de risco: um " +
                                      "atacante pode enviar uma requisição única com um payload malicioso nesse header e a " +
                                      "resposta envenenada pode ficar cacheada para TODOS os visitantes seguintes."
                                    : "Não foram detectados sinais claros de cache nesse alvo — o impacto real depende de " +
                                      "haver CDN/proxy reverso cacheando por URL sem considerar esse header, que precisa ser " +
                                      "confirmado manualmente."),
                            "Header enviado: " + header + ": " + valorMarcado + " | Refletido no corpo da resposta.",
                            "Configure a CDN/proxy reverso para incluir esse header na chave do cache (ou normalizá-lo/removê-lo " +
                                    "antes de cachear), e evite que a aplicação reflita headers de requisição diretamente no HTML.",
                            "1) CUIDADO: confirmar isso na prática pode afetar visitantes reais do site, então faça isso só com " +
                                    "autorização explícita pra esse tipo de teste. 2) Envie a requisição com o header malicioso " +
                                    "UMA VEZ, depois envie uma requisição NORMAL (sem o header) pra mesma URL e veja se a " +
                                    "resposta ainda contém o valor malicioso — isso confirma que ficou cacheado. 3) Use o header " +
                                    "'X-Cache' ou 'Age' na resposta pra confirmar se veio do cache ou da origem."));
                }
            } catch (Exception e) {
                api.logging().logToError("[Rx0] Erro no check de Cache Poisoning (header " + header + "): " + e.getMessage());
            }
        }
        return achados;
    }

    private boolean detectarCache(MontoyaApi api, String baseUrl) {
        try {
            HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(baseUrl)).response();
            if (resp == null) return false;
            for (HttpHeader h : resp.headers()) {
                String nome = h.name().toLowerCase();
                if (nome.equals("x-cache") || nome.equals("cf-cache-status") || nome.equals("age")
                        || nome.equals("x-varnish") || nome.equals("x-cdn") || nome.equals("x-served-by")) {
                    return true;
                }
            }
        } catch (Exception ignorado) {
            // segue sem detectar cache
        }
        return false;
    }
}
