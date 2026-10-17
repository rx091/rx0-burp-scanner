package com.rx0.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.rx0.burp.model.Finding;
import com.rx0.burp.report.HtmlReportGenerator;
import com.rx0.burp.scanner.ScanEngine;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Aba principal da extensão dentro do Burp: campo de alvo, botão de scan,
 * tabela de achados em tempo real e botão de gerar relatório HTML.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class Rx0Panel extends JPanel {

    private final MontoyaApi api;
    private final ScanEngine scanEngine = new ScanEngine();
    private final AtomicReference<List<Finding>> ultimoResultado = new AtomicReference<>();
    private String ultimoAlvo = "";

    private final JTextField campoAlvo = new JTextField();
    private final JButton botaoScan = new JButton("Iniciar scan");
    private final JButton botaoRelatorio = new JButton("Gerar relatório HTML");
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
        botaoRelatorio.addActionListener(e -> salvarRelatorio());
        botaoRelatorio.setEnabled(false);
    }

    private JPanel montarTopo() {
        JPanel topo = new JPanel(new BorderLayout(8, 0));
        JLabel label = new JLabel("Host/URL alvo:");
        campoAlvo.setToolTipText("Ex: https://alvo-autorizado.com");
        topo.add(label, BorderLayout.WEST);
        topo.add(campoAlvo, BorderLayout.CENTER);
        topo.add(botaoScan, BorderLayout.EAST);
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
        JPanel linha1 = new JPanel(new BorderLayout(8, 0));
        linha1.add(barraProgresso, BorderLayout.CENTER);
        linha1.add(botaoRelatorio, BorderLayout.EAST);
        rodape.add(linha1, BorderLayout.NORTH);
        rodape.add(statusLabel, BorderLayout.SOUTH);
        return rodape;
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
        ultimoAlvo = alvoFinal;

        modeloTabela.setRowCount(0);
        botaoScan.setEnabled(false);
        botaoRelatorio.setEnabled(false);
        barraProgresso.setMaximum(scanEngine.totalDeChecks());
        barraProgresso.setValue(0);
        statusLabel.setText("Iniciando scan em " + alvoFinal + " ...");

        SwingWorker<List<Finding>, Finding> worker = new SwingWorker<>() {
            @Override
            protected List<Finding> doInBackground() {
                return scanEngine.executarScanCompleto(api, alvoFinal, (nomeCheck, indice) -> {
                    SwingUtilities.invokeLater(() -> {
                        barraProgresso.setValue(indice);
                        statusLabel.setText("Executando: " + nomeCheck + " (" + indice + "/" + scanEngine.totalDeChecks() + ")");
                    });
                });
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
                    botaoRelatorio.setEnabled(true);
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

    private void salvarRelatorio() {
        List<Finding> achados = ultimoResultado.get();
        if (achados == null) {
            JOptionPane.showMessageDialog(this, "Rode um scan antes de gerar o relatório.", "Rx0 Scanner", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("relatorio-rx0-" + System.currentTimeMillis() + ".html"));
        int escolha = chooser.showSaveDialog(this);
        if (escolha != JFileChooser.APPROVE_OPTION) return;

        File destino = chooser.getSelectedFile();
        try (FileWriter writer = new FileWriter(destino)) {
            String html = new HtmlReportGenerator().gerar(ultimoAlvo, achados);
            writer.write(html);
            statusLabel.setText("Relatório salvo em: " + destino.getAbsolutePath());
            api.logging().logToOutput("[Rx0] Relatório salvo em " + destino.getAbsolutePath());
        } catch (Exception e) {
            statusLabel.setText("Erro ao salvar relatório: " + e.getMessage());
            api.logging().logToError("[Rx0] Erro ao salvar relatório: " + e.getMessage());
        }
    }
}
