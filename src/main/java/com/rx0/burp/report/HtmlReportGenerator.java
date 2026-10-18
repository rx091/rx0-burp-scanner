package com.rx0.burp.report;

import com.rx0.burp.model.Finding;
import com.rx0.burp.model.Severity;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Gera um relatório HTML standalone (sem dependências externas), com tema
 * escuro, resumo executivo por severidade e detalhamento de cada achado.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class HtmlReportGenerator {

    public String gerar(String alvo, List<Finding> achados) {
        List<Finding> ordenados = achados.stream()
                .sorted(Comparator.comparingInt((Finding f) -> f.getSeveridade().getWeight()).reversed())
                .toList();

        Map<Severity, Long> contagem = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) contagem.put(s, 0L);
        for (Finding f : achados) contagem.merge(f.getSeveridade(), 1L, Long::sum);

        String dataGeracao = LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy 'às' HH:mm:ss"));

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html lang=\"pt-BR\">\n<head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<title>Relatório de Segurança — ").append(escapeHtml(alvo)).append("</title>\n");
        html.append(css());
        html.append("</head>\n<body>\n");

        html.append("<div class=\"wrap\">\n");
        html.append("<header>\n");
        html.append("  <div class=\"brand\">Rx0 <span>Vulnerability Scanner</span></div>\n");
        html.append("  <h1>Relatório de Avaliação de Segurança</h1>\n");
        html.append("  <div class=\"meta\">\n");
        html.append("    <div><strong>Alvo:</strong> ").append(escapeHtml(alvo)).append("</div>\n");
        html.append("    <div><strong>Gerado em:</strong> ").append(dataGeracao).append("</div>\n");
        html.append("    <div><strong>Total de achados:</strong> ").append(achados.size()).append("</div>\n");
        html.append("  </div>\n");
        html.append("</header>\n");

        html.append("<section class=\"resumo\">\n<h2>Resumo por severidade</h2>\n<div class=\"cards\">\n");
        for (Severity s : new Severity[]{Severity.CRITICA, Severity.ALTA, Severity.MEDIA, Severity.BAIXA, Severity.INFO}) {
            html.append("  <div class=\"card\" style=\"border-color:").append(s.getColorHex()).append("\">\n");
            html.append("    <div class=\"card-num\" style=\"color:").append(s.getColorHex()).append("\">").append(contagem.get(s)).append("</div>\n");
            html.append("    <div class=\"card-label\">").append(s.name()).append("</div>\n");
            html.append("  </div>\n");
        }
        html.append("</div>\n</section>\n");

        html.append("<section class=\"achados\">\n<h2>Detalhamento dos achados</h2>\n");
        if (ordenados.isEmpty()) {
            html.append("<p class=\"vazio\">Nenhuma falha foi identificada pelos checks executados. Isso não significa ausência total de risco — recomenda-se complementar com testes manuais.</p>\n");
        }
        int idx = 1;
        for (Finding f : ordenados) {
            html.append("<div class=\"finding\" style=\"border-left-color:").append(f.getSeveridade().getColorHex()).append("\">\n");
            html.append("  <div class=\"finding-head\">\n");
            html.append("    <span class=\"sev\" style=\"background:").append(f.getSeveridade().getColorHex()).append("\">")
                    .append(f.getSeveridade().name()).append("</span>\n");
            html.append("    <h3>").append(idx++).append(". ").append(escapeHtml(f.getTitulo())).append("</h3>\n");
            html.append("  </div>\n");
            html.append("  <div class=\"finding-body\">\n");
            html.append("    <div class=\"field\"><span class=\"label\">URL:</span> <code>").append(escapeHtml(f.getUrl())).append("</code></div>\n");
            html.append("    <div class=\"field\"><span class=\"label\">Descrição:</span> ").append(escapeHtml(f.getDescricao())).append("</div>\n");
            html.append("    <div class=\"field\"><span class=\"label\">Evidência:</span> <code>").append(escapeHtml(f.getEvidencia())).append("</code></div>\n");
            html.append("    <div class=\"field\"><span class=\"label\">Recomendação:</span> ").append(escapeHtml(f.getRecomendacao())).append("</div>\n");
            html.append("    <div class=\"field timestamp\">Encontrado em: ").append(f.getEncontradoEmFormatado()).append("</div>\n");
            html.append("  </div>\n");
            html.append("</div>\n");
        }
        html.append("</section>\n");

        html.append("<footer>\n");
        html.append("  <p>Criado por <strong>Rx0</strong> — <a href=\"https://www.instagram.com/rodrigocoutinho91/\" target=\"_blank\" rel=\"noopener noreferrer\">@rodrigocoutinho91</a></p>\n");
        html.append("  <p class=\"disclaimer\">Relatório gerado automaticamente por scan próprio executado via extensão Burp Suite. ")
                .append("Resultados devem ser validados manualmente antes de qualquer ação corretiva ou divulgação. ")
                .append("Use apenas em ativos para os quais você possui autorização expressa de teste.</p>\n");
        html.append("</footer>\n");

        html.append("</div>\n</body>\n</html>");
        return html.toString();
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String css() {
        return """
            <style>
              :root {
                --bg: #0d0f14;
                --bg-panel: #151822;
                --bg-card: #1b1f2b;
                --border: #262c3b;
                --text: #e6e8ef;
                --text-dim: #9aa1b2;
                --accent: #7a5cff;
              }
              * { box-sizing: border-box; }
              body {
                margin: 0;
                background: var(--bg);
                color: var(--text);
                font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.5;
              }
              .wrap { max-width: 920px; margin: 0 auto; padding: 40px 24px 80px; }
              header {
                background: linear-gradient(135deg, var(--bg-panel), var(--bg-card));
                border: 1px solid var(--border);
                border-radius: 14px;
                padding: 28px 32px;
                margin-bottom: 32px;
              }
              .brand { font-size: 14px; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); font-weight: 700; }
              .brand span { color: var(--text-dim); font-weight: 400; }
              header h1 { margin: 8px 0 18px; font-size: 26px; }
              .meta { display: flex; flex-wrap: wrap; gap: 24px; color: var(--text-dim); font-size: 14px; }
              .meta strong { color: var(--text); }
              h2 { font-size: 18px; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-top: 40px; }
              .cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-top: 18px; }
              .card { background: var(--bg-card); border: 1px solid var(--border); border-left-width: 4px; border-radius: 10px; padding: 16px; text-align: center; }
              .card-num { font-size: 28px; font-weight: 700; }
              .card-label { font-size: 11px; letter-spacing: .06em; color: var(--text-dim); margin-top: 4px; }
              .finding { background: var(--bg-card); border: 1px solid var(--border); border-left-width: 5px; border-radius: 10px; padding: 18px 20px; margin-top: 16px; }
              .finding-head { display: flex; align-items: center; gap: 12px; }
              .finding-head h3 { margin: 0; font-size: 16px; }
              .sev { font-size: 10px; font-weight: 700; letter-spacing: .05em; color: #0d0f14; padding: 3px 9px; border-radius: 20px; white-space: nowrap; }
              .finding-body { margin-top: 12px; font-size: 14px; color: var(--text-dim); }
              .field { margin-top: 8px; }
              .field .label { color: var(--text); font-weight: 600; }
              code { background: #0a0c11; border: 1px solid var(--border); padding: 2px 6px; border-radius: 6px; color: #9fe6a0; font-size: 12.5px; word-break: break-all; }
              .timestamp { font-size: 11px; color: #5c6372; margin-top: 10px; }
              .vazio { color: var(--text-dim); font-style: italic; }
              footer { margin-top: 56px; border-top: 1px solid var(--border); padding-top: 20px; text-align: center; color: var(--text-dim); font-size: 13px; }
              footer a { color: var(--accent); text-decoration: none; }
              .disclaimer { max-width: 600px; margin: 10px auto 0; font-size: 11.5px; color: #5c6372; }
              @media (max-width: 700px) { .cards { grid-template-columns: repeat(2, 1fr); } }
            </style>
            """;
    }
}
