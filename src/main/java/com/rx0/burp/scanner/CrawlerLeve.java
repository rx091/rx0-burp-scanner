package com.rx0.burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Crawler propositalmente simples (não recursivo, só a página inicial): extrai
 * nomes de PARÂMETROS reais usados em links (?param=) e campos de formulário
 * (<input name="...">) do HTML. Isso é usado pelos checks de injeção pra testar
 * parâmetros que REALMENTE existem na aplicação, além da lista fixa de nomes
 * comuns que cada check já testa — aumenta a taxa de achado real sem remover
 * a cobertura "genérica" que já existia.
 *
 * Calculado UMA VEZ por scan (igual o FalsePositiveGuard), compartilhado via
 * ScanContext.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class CrawlerLeve {

    private static final Pattern PADRAO_QUERY_PARAM = Pattern.compile("[?&]([a-zA-Z0-9_\\[\\]]{1,40})=");
    private static final Pattern PADRAO_INPUT_NAME = Pattern.compile(
            "<input[^>]*name=[\"']([a-zA-Z0-9_\\[\\]]{1,40})[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern PADRAO_FORM_ACTION = Pattern.compile(
            "<form[^>]*action=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

    private final Set<String> parametrosDescobertos = new LinkedHashSet<>();
    private final Set<String> actionsDeFormulario = new LinkedHashSet<>();

    private CrawlerLeve() {
    }

    public static CrawlerLeve rastrear(MontoyaApi api, String baseUrl) {
        CrawlerLeve crawler = new CrawlerLeve();
        try {
            HttpResponse resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(baseUrl)).response();
            if (resp == null) return crawler;
            String body = resp.bodyToString();
            if (body == null) return crawler;

            Matcher mQuery = PADRAO_QUERY_PARAM.matcher(body);
            while (mQuery.find()) {
                crawler.parametrosDescobertos.add(mQuery.group(1));
            }

            Matcher mInput = PADRAO_INPUT_NAME.matcher(body);
            while (mInput.find()) {
                crawler.parametrosDescobertos.add(mInput.group(1));
            }

            Matcher mForm = PADRAO_FORM_ACTION.matcher(body);
            while (mForm.find()) {
                String action = mForm.group(1).trim();
                if (!action.isEmpty() && !action.startsWith("http")) {
                    crawler.actionsDeFormulario.add(action);
                }
            }

            if (!crawler.parametrosDescobertos.isEmpty()) {
                api.logging().logToOutput("[Rx0] Crawler: " + crawler.parametrosDescobertos.size()
                        + " parâmetro(s) real(is) descoberto(s) na página inicial: " + crawler.parametrosDescobertos);
            }
        } catch (Exception e) {
            api.logging().logToError("[Rx0] Erro no crawler leve: " + e.getMessage());
        }
        return crawler;
    }

    /** Parâmetros reais encontrados em links/formulários (pode ser vazio). */
    public Set<String> getParametrosDescobertos() {
        return parametrosDescobertos;
    }

    /** Paths de action de formulário encontrados (relativos), pode ser vazio. */
    public Set<String> getActionsDeFormulario() {
        return actionsDeFormulario;
    }
}
