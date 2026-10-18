package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.UUID;

/**
 * Calcula, UMA VEZ por scan, um "baseline" pedindo um path propositalmente
 * aleatório e inexistente. Isso detecta o caso mais comum de falso-positivo
 * em scanners de path/endpoint: aplicações SPA (React/Vue/Angular) ou
 * servidores mal configurados que respondem HTTP 200 com a MESMA página
 * (geralmente o index.html) para QUALQUER rota (catch-all / soft-404).
 *
 * Checks que testam paths (ex: SensitivePathsCheck, ApiEndpointDiscoveryCheck)
 * usam esse guard para descartar "achados" que na verdade são só esse
 * comportamento de catch-all, e não uma exposição real.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class FalsePositiveGuard {

    private final boolean provavelCatchAll;
    private final int statusBaseline;
    private final int tamanhoBaseline;
    private final String assinaturaConteudo; // primeiros 120 chars do corpo, pra comparação rápida

    private FalsePositiveGuard(boolean provavelCatchAll, int statusBaseline, int tamanhoBaseline, String assinaturaConteudo) {
        this.provavelCatchAll = provavelCatchAll;
        this.statusBaseline = statusBaseline;
        this.tamanhoBaseline = tamanhoBaseline;
        this.assinaturaConteudo = assinaturaConteudo;
    }

    public static FalsePositiveGuard calcular(MontoyaApi api, String baseUrl) {
        try {
            String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
            String pathAleatorio = "/rx0-caminho-que-nao-existe-" + UUID.randomUUID().toString().substring(0, 12);

            HttpRequest req = HttpRequest.httpRequestFromUrl(base + pathAleatorio);
            HttpResponse resp = api.http().sendRequest(req).response();
            if (resp == null) {
                return new FalsePositiveGuard(false, -1, -1, "");
            }

            String body = resp.bodyToString();
            int tamanho = body == null ? 0 : body.length();
            String assinatura = body == null ? "" : body.substring(0, Math.min(120, body.length()));

            // Se um path ALEATÓRIO E INEXISTENTE retorna 200, o servidor provavelmente
            // tem uma rota catch-all (comum em SPA) — todo check de path/endpoint
            // precisa comparar contra essa assinatura antes de reportar.
            boolean catchAll = resp.statusCode() == 200;

            api.logging().logToOutput("[Rx0] Baseline de falso-positivo: status=" + resp.statusCode()
                    + " | catch-all detectado=" + catchAll + " | tamanho do corpo=" + tamanho);

            return new FalsePositiveGuard(catchAll, resp.statusCode(), tamanho, assinatura);
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro ao calcular baseline de falso-positivo: " + e.getMessage());
            return new FalsePositiveGuard(false, -1, -1, "");
        }
    }

    /**
     * @return true se a resposta analisada bate com o padrão de catch-all detectado
     *         no baseline (ou seja, é provavelmente um falso-positivo, não uma
     *         exposição real daquele path específico).
     */
    public boolean pareceFalsoPositivo(int status, String body) {
        if (!provavelCatchAll) return false;
        if (status != statusBaseline) return false;

        int tamanho = body == null ? 0 : body.length();
        String assinatura = body == null ? "" : body.substring(0, Math.min(120, body.length()));

        boolean tamanhoParecido = Math.abs(tamanho - tamanhoBaseline) <= Math.max(40, (int) (tamanhoBaseline * 0.05));
        boolean assinaturaIgual = assinatura.equals(assinaturaConteudo);

        return tamanhoParecido && assinaturaIgual;
    }

    public boolean isProvavelCatchAll() {
        return provavelCatchAll;
    }
}
