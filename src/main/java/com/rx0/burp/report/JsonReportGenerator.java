package com.rx0.burp.report;

import com.rx0.burp.model.Finding;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Generates the report in JSON — useful for integrating with other tools
 * (importing into a spreadsheet, feeding a CI pipeline, etc).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class JsonReportGenerator {

    public String generate(String target, List<Finding> findings) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"created_by\": \"Rx0 - @rodrigocoutinho91\",\n");
        json.append("  \"target\": \"").append(escape(target)).append("\",\n");
        json.append("  \"generated_at\": \"").append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\",\n");
        json.append("  \"total_findings\": ").append(findings.size()).append(",\n");
        json.append("  \"findings\": [\n");

        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            json.append("    {\n");
            json.append("      \"title\": \"").append(escape(f.getTitle())).append("\",\n");
            json.append("      \"severity\": \"").append(f.getSeverity().name()).append("\",\n");
            json.append("      \"url\": \"").append(escape(f.getUrl())).append("\",\n");
            json.append("      \"description\": \"").append(escape(f.getDescription())).append("\",\n");
            json.append("      \"evidence\": \"").append(escape(f.getEvidence())).append("\",\n");
            json.append("      \"exploitation_steps\": \"").append(escape(f.getExploitationSteps())).append("\",\n");
            json.append("      \"recommendation\": \"").append(escape(f.getRecommendation())).append("\",\n");
            json.append("      \"found_at\": \"").append(f.getFoundAtFormatted()).append("\"\n");
            json.append("    }").append(i < findings.size() - 1 ? "," : "").append("\n");
        }

        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "")
                .replace("\t", "\\t");
    }
}
