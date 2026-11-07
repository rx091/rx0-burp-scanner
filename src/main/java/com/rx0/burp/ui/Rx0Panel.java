package com.rx0.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.rx0.burp.model.Finding;
import com.rx0.burp.report.CsvReportGenerator;
import com.rx0.burp.report.HtmlReportGenerator;
import com.rx0.burp.report.JsonReportGenerator;
import com.rx0.burp.scanner.ScanEngine;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Main tab of the extension inside Burp: target field, optional session cookie
 * field (authenticated scan), stealth mode, scan button, real-time findings
 * table, and export buttons (HTML/JSON/CSV).
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class Rx0Panel extends JPanel {

    private final MontoyaApi api;
    private final ScanEngine scanEngine = new ScanEngine();
    private final AtomicReference<List<Finding>> lastResult = new AtomicReference<>();
    private String lastTarget = "";

    private final JTextField targetField = new JTextField();
    private final JTextField cookieField = new JTextField();
    private final JCheckBox stealthCheckbox = new JCheckBox("Stealth mode (slower, more discreet)");
    private final JButton scanButton = new JButton("Start scan");
    private final JButton htmlReportButton = new JButton("HTML Report");
    private final JButton jsonReportButton = new JButton("Export JSON");
    private final JButton csvReportButton = new JButton("Export CSV");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel statusLabel = new JLabel("Ready.");
    private final DefaultTableModel tableModel = new DefaultTableModel(
            new Object[]{"Severity", "Finding", "URL"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };

    public Rx0Panel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);
        add(buildBottomPanel(), BorderLayout.SOUTH);

        scanButton.addActionListener(e -> triggerScan());
        htmlReportButton.addActionListener(e -> saveReport("html"));
        jsonReportButton.addActionListener(e -> saveReport("json"));
        csvReportButton.addActionListener(e -> saveReport("csv"));
        setReportButtonsEnabled(false);
    }

    private JPanel buildTopPanel() {
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        JPanel targetRow = new JPanel(new BorderLayout(8, 0));
        targetRow.add(new JLabel("Target host/URL:"), BorderLayout.WEST);
        targetField.setToolTipText("e.g.: https://authorized-target.com");
        targetRow.add(targetField, BorderLayout.CENTER);
        targetRow.add(scanButton, BorderLayout.EAST);
        targetRow.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JPanel cookieRow = new JPanel(new BorderLayout(8, 0));
        cookieRow.add(new JLabel("Session cookie (optional):"), BorderLayout.WEST);
        cookieField.setToolTipText("e.g.: sessionid=abc123; other=value — leave empty for an unauthenticated scan");
        cookieRow.add(cookieField, BorderLayout.CENTER);
        cookieRow.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JPanel stealthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        stealthRow.add(stealthCheckbox);

        top.add(targetRow);
        top.add(cookieRow);
        top.add(stealthRow);
        return top;
    }

    private JScrollPane buildCenterPanel() {
        JTable table = new JTable(tableModel);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setMaxWidth(90);
        return new JScrollPane(table);
    }

    private JPanel buildBottomPanel() {
        JPanel bottom = new JPanel(new BorderLayout(8, 4));
        progressBar.setStringPainted(true);

        JPanel exportButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        exportButtons.add(htmlReportButton);
        exportButtons.add(jsonReportButton);
        exportButtons.add(csvReportButton);

        JPanel row1 = new JPanel(new BorderLayout(8, 0));
        row1.add(progressBar, BorderLayout.CENTER);
        row1.add(exportButtons, BorderLayout.EAST);
        bottom.add(row1, BorderLayout.NORTH);
        bottom.add(statusLabel, BorderLayout.SOUTH);
        return bottom;
    }

    private void setReportButtonsEnabled(boolean enabled) {
        htmlReportButton.setEnabled(enabled);
        jsonReportButton.setEnabled(enabled);
        csvReportButton.setEnabled(enabled);
    }

    private void triggerScan() {
        String target = targetField.getText().trim();
        if (target.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Enter the URL of the host you are authorized to test.", "Rx0 Scanner", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!target.startsWith("http://") && !target.startsWith("https://")) {
            target = "https://" + target;
        }
        final String targetFinal = target;
        final String cookieFinal = cookieField.getText().trim();
        final boolean stealthFinal = stealthCheckbox.isSelected();
        lastTarget = targetFinal;

        tableModel.setRowCount(0);
        scanButton.setEnabled(false);
        setReportButtonsEnabled(false);
        progressBar.setMaximum(scanEngine.totalChecks());
        progressBar.setValue(0);
        statusLabel.setText("Starting scan on " + targetFinal
                + (cookieFinal.isEmpty() ? "" : " (authenticated)")
                + (stealthFinal ? " [stealth mode]" : "") + " ...");

        SwingWorker<List<Finding>, Finding> worker = new SwingWorker<>() {
            @Override
            protected List<Finding> doInBackground() {
                return scanEngine.runFullScan(api, targetFinal, (checkName, index) -> {
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setValue(Math.min(index, scanEngine.totalChecks()));
                        statusLabel.setText("Running: " + checkName + " (" + index + "/" + scanEngine.totalChecks() + ")");
                    });
                }, cookieFinal.isEmpty() ? null : cookieFinal, stealthFinal);
            }

            @Override
            protected void done() {
                try {
                    List<Finding> findings = get();
                    lastResult.set(findings);
                    for (Finding f : findings) {
                        tableModel.addRow(new Object[]{f.getSeverity().name(), f.getTitle(), f.getUrl()});
                    }
                    statusLabel.setText("Scan finished — " + findings.size() + " finding(s) on " + targetFinal + ".");
                    setReportButtonsEnabled(true);
                    api.logging().logToOutput("[Rx0] Scan completed on " + targetFinal + " — " + findings.size() + " findings.");
                } catch (Exception ex) {
                    statusLabel.setText("Error during scan: " + ex.getMessage());
                    api.logging().logToError("[Rx0] Scan error: " + ex.getMessage());
                } finally {
                    scanButton.setEnabled(true);
                }
            }
        };
        worker.execute();
    }

    private void saveReport(String format) {
        List<Finding> findings = lastResult.get();
        if (findings == null) {
            JOptionPane.showMessageDialog(this, "Run a scan before generating the report.", "Rx0 Scanner", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String extension = format.equals("json") ? ".json" : format.equals("csv") ? ".csv" : ".html";
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("rx0-report-" + System.currentTimeMillis() + extension));
        int choice = chooser.showSaveDialog(this);
        if (choice != JFileChooser.APPROVE_OPTION) return;

        File destinationFile = chooser.getSelectedFile();
        try (FileWriter writer = new FileWriter(destinationFile)) {
            String content;
            switch (format) {
                case "json":
                    content = new JsonReportGenerator().generate(lastTarget, findings);
                    break;
                case "csv":
                    content = new CsvReportGenerator().generate(findings);
                    break;
                default:
                    content = new HtmlReportGenerator().generate(lastTarget, findings);
            }
            writer.write(content);
            statusLabel.setText("Report (" + format.toUpperCase() + ") saved to: " + destinationFile.getAbsolutePath());
            api.logging().logToOutput("[Rx0] Report (" + format + ") saved to " + destinationFile.getAbsolutePath());
        } catch (Exception e) {
            statusLabel.setText("Error saving report: " + e.getMessage());
            api.logging().logToError("[Rx0] Error saving report: " + e.getMessage());
        }
    }
}
