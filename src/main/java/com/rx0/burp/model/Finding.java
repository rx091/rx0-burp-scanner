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
    private final LocalDateTime encontradoEm;

    public Finding(String titulo, Severity severidade, String url, String descricao,
                    String evidencia, String recomendacao) {
        this.titulo = titulo;
        this.severidade = severidade;
        this.url = url;
        this.descricao = descricao;
        this.evidencia = evidencia;
        this.recomendacao = recomendacao;
        this.encontradoEm = LocalDateTime.now();
    }

    public String getTitulo() { return titulo; }
    public Severity getSeveridade() { return severidade; }
    public String getUrl() { return url; }
    public String getDescricao() { return descricao; }
    public String getEvidencia() { return evidencia; }
    public String getRecomendacao() { return recomendacao; }

    public String getEncontradoEmFormatado() {
        return encontradoEm.format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss"));
    }
}
