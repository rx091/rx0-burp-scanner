package com.rx0.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.rx0.burp.ui.Rx0Panel;

/**
 * Ponto de entrada da extensão Rx0 Vulnerability Scanner para Burp Suite.
 *
 * Registra uma aba própria na interface do Burp com:
 *  - campo para informar o host/URL alvo (autorizado para teste)
 *  - botão para rodar os checks de vulnerabilidade
 *  - tabela de achados em tempo real
 *  - geração de relatório HTML com tema escuro
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class Rx0ScannerExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Rx0 Vulnerability Scanner");

        api.logging().logToOutput(
                "[Rx0] Extensão carregada — Rx0 Vulnerability Scanner v1.0.0\n" +
                "[Rx0] Criado por Rx0 - @rodrigocoutinho91\n" +
                "[Rx0] Use apenas em hosts para os quais você possui autorização de teste."
        );

        Rx0Panel painel = new Rx0Panel(api);
        api.userInterface().registerSuiteTab("Rx0 Scanner", painel);
    }
}
