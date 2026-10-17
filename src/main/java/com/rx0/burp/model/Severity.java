package com.rx0.burp.model;

/**
 * Níveis de severidade das falhas encontradas.
 * Criado por Rx0 - @rodrigocoutinho91
 */
public enum Severity {
    CRITICA(4, "#ff3b5c"),
    ALTA(3, "#ff8a3d"),
    MEDIA(2, "#ffd23d"),
    BAIXA(1, "#3dd6ff"),
    INFO(0, "#7a7a7a");

    private final int weight;
    private final String colorHex;

    Severity(int weight, String colorHex) {
        this.weight = weight;
        this.colorHex = colorHex;
    }

    public int getWeight() {
        return weight;
    }

    public String getColorHex() {
        return colorHex;
    }
}
