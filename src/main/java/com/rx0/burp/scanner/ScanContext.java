package com.rx0.burp.scanner;

/**
 * Agrupa os recursos compartilhados entre todos os checks de um mesmo scan:
 * o guard de falso-positivo (detecção de catch-all/SPA) e o cliente interactsh
 * (confirmação out-of-band). Calculado/iniciado UMA VEZ por scan no ScanEngine
 * e passado pra cada check — qualquer check pode ignorar o que não usa.
 *
 * Criado por Rx0 - @rodrigocoutinho91
 */
public class ScanContext {

    private final FalsePositiveGuard guard;
    private final InteractshClient interactsh;

    public ScanContext(FalsePositiveGuard guard, InteractshClient interactsh) {
        this.guard = guard;
        this.interactsh = interactsh;
    }

    public FalsePositiveGuard guard() {
        return guard;
    }

    public InteractshClient interactsh() {
        return interactsh;
    }
}
