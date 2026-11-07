package com.rx0.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.rx0.burp.ui.Rx0Panel;

/**
 * Entry point of the Rx0 Vulnerability Scanner extension for Burp Suite.
 *
 * Registers a dedicated tab in the Burp UI with:
 *  - a field to enter the target host/URL (authorized for testing)
 *  - a button to run the vulnerability checks
 *  - a real-time table of findings
 *  - dark-themed HTML report generation
 *
 * Created by Rx0 - @rodrigocoutinho91
 */
public class Rx0ScannerExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Rx0 Vulnerability Scanner");

        api.logging().logToOutput(
                "[Rx0] Extension loaded — Rx0 Vulnerability Scanner v1.0.0\n" +
                "[Rx0] Created by Rx0 - @rodrigocoutinho91\n" +
                "[Rx0] Only use against hosts you are authorized to test."
        );

        Rx0Panel panel = new Rx0Panel(api);
        api.userInterface().registerSuiteTab("Rx0 Scanner", panel);
    }
}
