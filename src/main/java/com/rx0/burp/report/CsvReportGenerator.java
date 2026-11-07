package com.rx0.burp.report;

import com.rx0.burp.model.Finding;

import java.util.List;

/**
 * Generates the report in CSV — for importing directly into a spreadsheet
 * (Excel/Google Sheets) to track findings.
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class CsvReportGenerator {

    public String generate(List<Finding> findings) {
        StringBuilder csv = new StringBuilder();
        csv.append("Severity;Title;URL;Description;Evidence;Exploitation Steps;Recommendation;Found At\n");

        for (Finding f : findings) {
            csv.append(field(f.getSeverity().name())).append(";");
            csv.append(field(f.getTitle())).append(";");
            csv.append(field(f.getUrl())).append(";");
            csv.append(field(f.getDescription())).append(";");
            csv.append(field(f.getEvidence())).append(";");
            csv.append(field(f.getExploitationSteps())).append(";");
            csv.append(field(f.getRecommendation())).append(";");
            csv.append(field(f.getFoundAtFormatted())).append("\n");
        }
        return csv.toString();
    }

    // Escapes double quotes and wraps the field in quotes (CSV standard), since the
    // description/evidence may contain ';' or line breaks
    private String field(String value) {
        if (value == null) return "\"\"";
        return "\"" + value.replace("\"", "\"\"").replace("\n", " ").replace("\r", "") + "\"";
    }
}
