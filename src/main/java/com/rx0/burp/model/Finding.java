package com.rx0.burp.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Representa uma falha/achado encontrado durante o scan.
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class Finding {

    private final String titulo;
    private final Severity severidade;
    private final String url;
    private final String descricao;
    private final String evidencia;
    private final String recomendacao;
    private final String modoExploracao;
    private final LocalDateTime encontradoEm;

    /**
     * Construtor completo — inclui o modo de exploração (passo a passo de como
     * reproduzir/validar manualmente o achado). Prefira este construtor para
     * achados de severidade CRITICA/ALTA, onde o passo a passo tem mais valor.
     */
    public Finding(String titulo, Severity severidade, String url, String descricao,
                    String evidencia, String recomendacao, String modoExploracao) {
        this.titulo = titulo;
        this.severidade = severidade;
        this.url = url;
        this.descricao = descricao;
        this.evidencia = evidencia;
        this.recomendacao = recomendacao;
        this.modoExploracao = (modoExploracao == null || modoExploracao.isBlank())
                ? modoExploracaoPadrao(url, evidencia)
                : modoExploracao;
        this.encontradoEm = LocalDateTime.now();
    }

    /**
     * Construtor retrocompatível (sem modo de exploração explícito) — gera um
     * modo de exploração genérico a partir da URL e evidência já coletadas.
     */
    public Finding(String titulo, Severity severidade, String url, String descricao,
                    String evidencia, String recomendacao) {
        this(titulo, severidade, url, descricao, evidencia, recomendacao, null);
    }

    private static String modoExploracaoPadrao(String url, String evidencia) {
        return "Reproduza manualmente a requisição que gerou este achado (URL: " + url + "). " +
                "Use o Repeater do Burp para reenviar a requisição e observar a evidência descrita (" +
                (evidencia != null && evidencia.length() > 80 ? evidencia.substring(0, 80) + "..." : evidencia) +
                ") diretamente na resposta, confirmando o comportamento antes de qualquer ação corretiva.";
    }

    public String getTitulo() { return titulo; }
    public Severity getSeveridade() { return severidade; }
    public String getUrl() { return url; }
    public String getDescricao() { return descricao; }
    public String getEvidencia() { return evidencia; }
    public String getRecomendacao() { return recomendacao; }
    public String getModoExploracao() { return modoExploracao; }

    public String getEncontradoEmFormatado() {
        return encontradoEm.format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss"));
    }
}
