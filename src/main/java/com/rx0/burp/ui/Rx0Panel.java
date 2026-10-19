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
 * Aba principal da extensão dentro do Burp: campo de alvo, campo opcional de
 * cookie de sessão (scan autenticado), modo stealth, botão de scan, tabela de
 * achados em tempo real e botões de exportação (HTML/JSON/CSV).
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class Rx0Panel extends JPanel {

    private final MontoyaApi api;
    private final ScanEngine scanEngine = new ScanEngine();
    private final AtomicReference<List<Finding>> ultimoResultado = new AtomicReference<>();
    private String ultimoAlvo = "";

    private final JTextField campoAlvo = new JTextField();
    private final JTextField campoCookie = new JTextField();
    private final JCheckBox checkStealth = new JCheckBox("Modo stealth (mais lento, mais discreto)");
    private final JButton botaoScan = new JButton("Iniciar scan");
    private final JButton botaoRelatorioHtml = new JButton("Relatório HTML");
    private final JButton botaoRelatorioJson = new JButton("Exportar JSON");
    private final JButton botaoRelatorioCsv = new JButton("Exportar CSV");
    private final JProgressBar barraProgresso = new JProgressBar();
    private final JLabel statusLabel = new JLabel("Pronto.");
    private final DefaultTableModel modeloTabela = new DefaultTableModel(
            new Object[]{"Severidade", "Achado", "URL"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };

    public Rx0Panel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        add(montarTopo(), BorderLayout.NORTH);
        add(montarCentro(), BorderLayout.CENTER);
        add(montarRodape(), BorderLayout.SOUTH);

        botaoScan.addActionListener(e -> dispararScan());
        botaoRelatorioHtml.addActionListener(e -> salvarRelatorio("html"));
        botaoRelatorioJson.addActionListener(e -> salvarRelatorio("json"));
        botaoRelatorioCsv.addActionListener(e -> salvarRelatorio("csv"));
        setBotoesRelatorioHabilitados(false);
    }

    private JPanel montarTopo() {
        JPanel topo = new JPanel();
        topo.setLayout(new BoxLayout(topo, BoxLayout.Y_AXIS));

        JPanel linhaAlvo = new JPanel(new BorderLayout(8, 0));
        linhaAlvo.add(new JLabel("Host/URL alvo:"), BorderLayout.WEST);
        campoAlvo.setToolTipText("Ex: https://alvo-autorizado.com");
        linhaAlvo.add(campoAlvo, BorderLayout.CENTER);
        linhaAlvo.add(botaoScan, BorderLayout.EAST);
        linhaAlvo.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JPanel linhaCookie = new JPanel(new BorderLayout(8, 0));
        linhaCookie.add(new JLabel("Cookie de sessão (opcional):"), BorderLayout.WEST);
        campoCookie.setToolTipText("Ex: sessionid=abc123; outro=valor — deixe vazio pra scan sem autenticação");
        linhaCookie.add(campoCookie, BorderLayout.CENTER);
        linhaCookie.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JPanel linhaStealth = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        linhaStealth.add(checkStealth);

        topo.add(linhaAlvo);
        topo.add(linhaCookie);
        topo.add(linhaStealth);
        return topo;
    }

    private JScrollPane montarCentro() {
        JTable tabela = new JTable(modeloTabela);
        tabela.setRowHeight(22);
        tabela.getColumnModel().getColumn(0).setMaxWidth(90);
        return new JScrollPane(tabela);
    }

    private JPanel montarRodape() {
        JPanel rodape = new JPanel(new BorderLayout(8, 4));
        barraProgresso.setStringPainted(true);

        JPanel botoesExport = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        botoesExport.add(botaoRelatorioHtml);
        botoesExport.add(botaoRelatorioJson);
        botoesExport.add(botaoRelatorioCsv);

        JPanel linha1 = new JPanel(new BorderLayout(8, 0));
        linha1.add(barraProgresso, BorderLayout.CENTER);
        linha1.add(botoesExport, BorderLayout.EAST);
        rodape.add(linha1, BorderLayout.NORTH);
        rodape.add(statusLabel, BorderLayout.SOUTH);
        return rodape;
    }

    private void setBotoesRelatorioHabilitados(boolean habilitado) {
        botaoRelatorioHtml.setEnabled(habilitado);
        botaoRelatorioJson.setEnabled(habilitado);
        botaoRelatorioCsv.setEnabled(habilitado);
    }

    private void dispararScan() {
        String alvo = campoAlvo.getText().trim();
        if (alvo.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Informe a URL do host que você está autorizado a testar.", "Rx0 Scanner", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!alvo.startsWith("http://") && !alvo.startsWith("https://")) {
            alvo = "https://" + alvo;
        }
        final String alvoFinal = alvo;
        final String cookieFinal = campoCookie.getText().trim();
        final boolean stealthFinal = checkStealth.isSelected();
        ultimoAlvo = alvoFinal;

        modeloTabela.setRowCount(0);
        botaoScan.setEnabled(false);
        setBotoesRelatorioHabilitados(false);
        barraProgresso.setMaximum(scanEngine.totalDeChecks());
        barraProgresso.setValue(0);
        statusLabel.setText("Iniciando scan em " + alvoFinal
                + (cookieFinal.isEmpty() ? "" : " (autenticado)")
                + (stealthFinal ? " [modo stealth]" : "") + " ...");

        SwingWorker<List<Finding>, Finding> worker = new SwingWorker<>() {
            @Override
            protected List<Finding> doInBackground() {
                return scanEngine.executarScanCompleto(api, alvoFinal, (nomeCheck, indice) -> {
                    SwingUtilities.invokeLater(() -> {
                        barraProgresso.setValue(Math.min(indice, scanEngine.totalDeChecks()));
                        statusLabel.setText("Executando: " + nomeCheck + " (" + indice + "/" + scanEngine.totalDeChecks() + ")");
                    });
                }, cookieFinal.isEmpty() ? null : cookieFinal, stealthFinal);
            }

            @Override
            protected void done() {
                try {
                    List<Finding> achados = get();
                    ultimoResultado.set(achados);
                    for (Finding f : achados) {
                        modeloTabela.addRow(new Object[]{f.getSeveridade().name(), f.getTitulo(), f.getUrl()});
                    }
                    statusLabel.setText("Scan finalizado — " + achados.size() + " achado(s) em " + alvoFinal + ".");
                    setBotoesRelatorioHabilitados(true);
                    api.logging().logToOutput("[Rx0] Scan concluído em " + alvoFinal + " — " + achados.size() + " achados.");
                } catch (Exception ex) {
                    statusLabel.setText("Erro durante o scan: " + ex.getMessage());
                    api.logging().logToError("[Rx0] Erro no scan: " + ex.getMessage());
                } finally {
                    botaoScan.setEnabled(true);
                }
            }
        };
        worker.execute();
    }

    private void salvarRelatorio(String formato) {
        List<Finding> achados = ultimoResultado.get();
        if (achados == null) {
            JOptionPane.showMessageDialog(this, "Rode um scan antes de gerar o relatório.", "Rx0 Scanner", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String extensao = formato.equals("json") ? ".json" : formato.equals("csv") ? ".csv" : ".html";
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("relatorio-rx0-" + System.currentTimeMillis() + extensao));
        int escolha = chooser.showSaveDialog(this);
        if (escolha != JFileChooser.APPROVE_OPTION) return;

        File destino = chooser.getSelectedFile();
        try (FileWriter writer = new FileWriter(destino)) {
            String conteudo;
            switch (formato) {
                case "json":
                    conteudo = new JsonReportGenerator().gerar(ultimoAlvo, achados);
                    break;
                case "csv":
                    conteudo = new CsvReportGenerator().gerar(achados);
                    break;
                default:
                    conteudo = new HtmlReportGenerator().gerar(ultimoAlvo, achados);
            }
            writer.write(conteudo);
            statusLabel.setText("Relatório (" + formato.toUpperCase() + ") salvo em: " + destino.getAbsolutePath());
            api.logging().logToOutput("[Rx0] Relatório (" + formato + ") salvo em " + destino.getAbsolutePath());
        } catch (Exception e) {
            statusLabel.setText("Erro ao salvar relatório: " + e.getMessage());
            api.logging().logToError("[Rx0] Erro ao salvar relatório: " + e.getMessage());
        }
    }
}
