package com.rx0.burp.report;

import com.rx0.burp.model.Finding;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Gera o relatório em JSON — útil para integrar com outras ferramentas
 * (importar numa planilha, alimentar um pipeline de CI, etc).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class JsonReportGenerator {

    public String gerar(String alvo, List<Finding> achados) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"criado_por\": \"Rx0 - @rodrigocoutinho91\",\n");
        json.append("  \"alvo\": \"").append(escapar(alvo)).append("\",\n");
        json.append("  \"gerado_em\": \"").append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\",\n");
        json.append("  \"total_achados\": ").append(achados.size()).append(",\n");
        json.append("  \"achados\": [\n");

        for (int i = 0; i < achados.size(); i++) {
            Finding f = achados.get(i);
            json.append("    {\n");
            json.append("      \"titulo\": \"").append(escapar(f.getTitulo())).append("\",\n");
            json.append("      \"severidade\": \"").append(f.getSeveridade().name()).append("\",\n");
            json.append("      \"url\": \"").append(escapar(f.getUrl())).append("\",\n");
            json.append("      \"descricao\": \"").append(escapar(f.getDescricao())).append("\",\n");
            json.append("      \"evidencia\": \"").append(escapar(f.getEvidencia())).append("\",\n");
            json.append("      \"modo_exploracao\": \"").append(escapar(f.getModoExploracao())).append("\",\n");
            json.append("      \"recomendacao\": \"").append(escapar(f.getRecomendacao())).append("\",\n");
            json.append("      \"encontrado_em\": \"").append(f.getEncontradoEmFormatado()).append("\"\n");
            json.append("    }").append(i < achados.size() - 1 ? "," : "").append("\n");
        }

        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private String escapar(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "")
                .replace("\t", "\\t");
    }
}
