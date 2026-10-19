package com.rx0.burp.report;

import com.rx0.burp.model.Finding;

import java.util.List;

/**
 * Gera o relatório em CSV — pra importar direto numa planilha de tracking
 * de findings (Excel/Google Sheets).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class CsvReportGenerator {

    public String gerar(List<Finding> achados) {
        StringBuilder csv = new StringBuilder();
        csv.append("Severidade;Titulo;URL;Descricao;Evidencia;Modo de Exploracao;Recomendacao;Encontrado em\n");

        for (Finding f : achados) {
            csv.append(campo(f.getSeveridade().name())).append(";");
            csv.append(campo(f.getTitulo())).append(";");
            csv.append(campo(f.getUrl())).append(";");
            csv.append(campo(f.getDescricao())).append(";");
            csv.append(campo(f.getEvidencia())).append(";");
            csv.append(campo(f.getModoExploracao())).append(";");
            csv.append(campo(f.getRecomendacao())).append(";");
            csv.append(campo(f.getEncontradoEmFormatado())).append("\n");
        }
        return csv.toString();
    }

    // Escapa aspas duplas e envolve o campo em aspas (padrão CSV), já que a descrição/evidência pode conter ';' ou quebras de linha
    private String campo(String valor) {
        if (valor == null) return "\"\"";
        return "\"" + valor.replace("\"", "\"\"").replace("\n", " ").replace("\r", "") + "\"";
    }
}
