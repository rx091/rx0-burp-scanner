package com.rx0.burp.scanner;

/**
 * Agrupa os recursos compartilhados entre todos os checks de um mesmo scan:
 * o guard de falso-positivo (detecção de catch-all/SPA) e o cliente interactsh
 * (confirmação out-of-band). Calculado/iniciado UMA VEZ por scan no ScanEngine
 * e passado pra cada check — qualquer check pode ignorar o que não usa.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class ScanContext {

    private final FalsePositiveGuard guard;
    private final InteractshClient interactsh;
    private final CrawlerLeve crawler;
    private final String cookieAutenticacao; // pode ser null/vazio — scan sem sessão

    public ScanContext(FalsePositiveGuard guard, InteractshClient interactsh, CrawlerLeve crawler, String cookieAutenticacao) {
        this.guard = guard;
        this.interactsh = interactsh;
        this.crawler = crawler;
        this.cookieAutenticacao = cookieAutenticacao;
    }

    public FalsePositiveGuard guard() {
        return guard;
    }

    public InteractshClient interactsh() {
        return interactsh;
    }

    public CrawlerLeve crawler() {
        return crawler;
    }

    /** @return o valor do header Cookie a aplicar nas requisições, ou null se não configurado. */
    public String cookieAutenticacao() {
        return (cookieAutenticacao == null || cookieAutenticacao.isBlank()) ? null : cookieAutenticacao;
    }

    public boolean temAutenticacao() {
        return cookieAutenticacao() != null;
    }

    /** Aplica o cookie de autenticação (se configurado) numa requisição. Uso: req = ctx.comAuth(req). */
    public burp.api.montoya.http.message.requests.HttpRequest comAuth(burp.api.montoya.http.message.requests.HttpRequest req) {
        if (temAutenticacao()) {
            return req.withAddedHeader("Cookie", cookieAutenticacao());
        }
        return req;
    }
}
