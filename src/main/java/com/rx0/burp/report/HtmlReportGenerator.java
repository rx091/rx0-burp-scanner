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
 * Generates a standalone HTML report (no external dependencies), with a dark
 * theme, an executive summary by severity, and a detailed breakdown of each finding.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class HtmlReportGenerator {

    public String generate(String target, List<Finding> findings) {
        List<Finding> sorted = findings.stream()
                .sorted(Comparator.comparingInt((Finding f) -> f.getSeverity().getWeight()).reversed())
                .toList();

        Map<Severity, Long> countBySeverity = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) countBySeverity.put(s, 0L);
        for (Finding f : findings) countBySeverity.merge(f.getSeverity(), 1L, Long::sum);

        String generatedAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd 'at' HH:mm:ss"));

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<title>Security Report — ").append(escapeHtml(target)).append("</title>\n");
        html.append(css());
        html.append("</head>\n<body>\n");

        html.append("<div class=\"wrap\">\n");
        html.append("<header>\n");
        html.append("  <div class=\"brand\">Rx0 <span>Vulnerability Scanner</span></div>\n");
        html.append("  <h1>Security Assessment Report</h1>\n");
        html.append("  <div class=\"meta\">\n");
        html.append("    <div><strong>Target:</strong> ").append(escapeHtml(target)).append("</div>\n");
        html.append("    <div><strong>Generated at:</strong> ").append(generatedAt).append("</div>\n");
        html.append("    <div><strong>Total findings:</strong> ").append(findings.size()).append("</div>\n");
        html.append("  </div>\n");
        html.append("</header>\n");

        if (!sorted.isEmpty()) {
            html.append("<section class=\"top5\">\n<h2>Top 5 risks</h2>\n<ol class=\"top5-list\">\n");
            int limit = Math.min(5, sorted.size());
            for (int i = 0; i < limit; i++) {
                Finding f = sorted.get(i);
                html.append("  <li style=\"border-left-color:").append(f.getSeverity().getColorHex()).append("\">")
                        .append("<span class=\"sev-inline\" style=\"background:").append(f.getSeverity().getColorHex()).append("\">")
                        .append(f.getSeverity().name()).append("</span> ")
                        .append(escapeHtml(f.getTitle())).append("</li>\n");
            }
            html.append("</ol>\n</section>\n");
        }

        html.append("<section class=\"summary\">\n<h2>Summary by severity</h2>\n<div class=\"cards\">\n");
        for (Severity s : new Severity[]{Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}) {
            html.append("  <div class=\"card\" style=\"border-color:").append(s.getColorHex()).append("\">\n");
            html.append("    <div class=\"card-num\" style=\"color:").append(s.getColorHex()).append("\">").append(countBySeverity.get(s)).append("</div>\n");
            html.append("    <div class=\"card-label\">").append(s.name()).append("</div>\n");
            html.append("  </div>\n");
        }
        html.append("</div>\n</section>\n");

        html.append("<section class=\"findings\">\n<h2>Finding details</h2>\n");
        if (sorted.isEmpty()) {
            html.append("<p class=\"empty\">No issues were identified by the checks that ran. This does not mean the target is risk-free — complementing this with manual testing is recommended.</p>\n");
        }
        int idx = 1;
        for (Finding f : sorted) {
            html.append("<div class=\"finding\" style=\"border-left-color:").append(f.getSeverity().getColorHex()).append("\">\n");
            html.append("  <div class=\"finding-head\">\n");
            html.append("    <span class=\"sev\" style=\"background:").append(f.getSeverity().getColorHex()).append("\">")
                    .append(f.getSeverity().name()).append("</span>\n");
            html.append("    <h3>").append(idx++).append(". ").append(escapeHtml(f.getTitle())).append("</h3>\n");
            html.append("  </div>\n");
            html.append("  <div class=\"finding-body\">\n");
            html.append("    <div class=\"field\"><span class=\"label\">URL:</span> <code>").append(escapeHtml(f.getUrl())).append("</code></div>\n");
            html.append("    <div class=\"field\"><span class=\"label\">Description:</span> ").append(escapeHtml(f.getDescription())).append("</div>\n");
            html.append("    <div class=\"field\"><span class=\"label\">Evidence:</span> <code>").append(escapeHtml(f.getEvidence())).append("</code></div>\n");
            html.append("    <div class=\"field exploit\"><span class=\"label\">Exploitation steps:</span> ").append(escapeHtml(f.getExploitationSteps())).append("</div>\n");
            html.append("    <div class=\"field\"><span class=\"label\">Recommendation:</span> ").append(escapeHtml(f.getRecommendation())).append("</div>\n");
            html.append("    <div class=\"field timestamp\">Found at: ").append(f.getFoundAtFormatted()).append("</div>\n");
            html.append("  </div>\n");
            html.append("</div>\n");
        }
        html.append("</section>\n");

        html.append("<footer>\n");
        html.append("  <p>Created by <strong>Rx0</strong> — <a href=\"https://www.instagram.com/rodrigocoutinho91/\" target=\"_blank\" rel=\"noopener noreferrer\">@rodrigocoutinho91</a></p>\n");
        html.append("  <p class=\"disclaimer\">This report was generated automatically by a self-run scan executed via a Burp Suite extension. ")
                .append("Results should be manually validated before any remediation action or disclosure. ")
                .append("Only use this against assets you have express authorization to test.</p>\n");
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
              .top5-list { list-style: none; margin: 16px 0 0; padding: 0; counter-reset: top5; }
              .top5-list li { counter-increment: top5; background: var(--bg-card); border: 1px solid var(--border); border-left-width: 4px; border-radius: 8px; padding: 12px 16px; margin-top: 8px; font-size: 14px; }
              .top5-list li::before { content: counter(top5) ". "; font-weight: 700; color: var(--accent); }
              .sev-inline { font-size: 10px; font-weight: 700; color: #0d0f14; padding: 2px 8px; border-radius: 20px; margin-right: 6px; }
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
              .field.exploit { background: #1a1424; border: 1px solid #3a2a5c; border-radius: 8px; padding: 10px 12px; margin-top: 10px; }
              .field.exploit .label { color: var(--accent); }
              code { background: #0a0c11; border: 1px solid var(--border); padding: 2px 6px; border-radius: 6px; color: #9fe6a0; font-size: 12.5px; word-break: break-all; }
              .timestamp { font-size: 11px; color: #5c6372; margin-top: 10px; }
              .empty { color: var(--text-dim); font-style: italic; }
              footer { margin-top: 56px; border-top: 1px solid var(--border); padding-top: 20px; text-align: center; color: var(--text-dim); font-size: 13px; }
              footer a { color: var(--accent); text-decoration: none; }
              .disclaimer { max-width: 600px; margin: 10px auto 0; font-size: 11.5px; color: #5c6372; }
              @media (max-width: 700px) { .cards { grid-template-columns: repeat(2, 1fr); } }
            </style>
            """;
    }
}
