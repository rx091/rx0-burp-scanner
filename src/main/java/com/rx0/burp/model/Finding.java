package com.rx0.burp.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents a finding/vulnerability discovered during the scan.
 * Created by Rx0 - @rodrigocoutinho91
 */
public class Finding {

    private final String title;
    private final Severity severity;
    private final String url;
    private final String description;
    private final String evidence;
    private final String recommendation;
    private final String exploitationSteps;
    private final LocalDateTime foundAt;

    /**
     * Full constructor — includes explicit exploitation steps (a step-by-step
     * guide on how to manually reproduce/validate the finding). Prefer this
     * constructor for CRITICAL/HIGH severity findings, where the walkthrough
     * adds the most value.
     */
    public Finding(String title, Severity severity, String url, String description,
                    String evidence, String recommendation, String exploitationSteps) {
        this.title = title;
        this.severity = severity;
        this.url = url;
        this.description = description;
        this.evidence = evidence;
        this.recommendation = recommendation;
        this.exploitationSteps = (exploitationSteps == null || exploitationSteps.isBlank())
                ? defaultExploitationSteps(url, evidence)
                : exploitationSteps;
        this.foundAt = LocalDateTime.now();
    }

    /**
     * Backward-compatible constructor (no explicit exploitation steps) — generates
     * a generic exploitation walkthrough from the URL and evidence already collected.
     */
    public Finding(String title, Severity severity, String url, String description,
                    String evidence, String recommendation) {
        this(title, severity, url, description, evidence, recommendation, null);
    }

    private static String defaultExploitationSteps(String url, String evidence) {
        return "Manually reproduce the request that produced this finding (URL: " + url + "). " +
                "Use Burp Repeater to resend the request and observe the described evidence (" +
                (evidence != null && evidence.length() > 80 ? evidence.substring(0, 80) + "..." : evidence) +
                ") directly in the response, confirming the behavior before any remediation action.";
    }

    public String getTitle() { return title; }
    public Severity getSeverity() { return severity; }
    public String getUrl() { return url; }
    public String getDescription() { return description; }
    public String getEvidence() { return evidence; }
    public String getRecommendation() { return recommendation; }
    public String getExploitationSteps() { return exploitationSteps; }

    public String getFoundAtFormatted() {
        return foundAt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
}
