package com.rx0.burp.model;

/**
 * Severity levels for the findings discovered.
 * Created by Rx0 - @rodrigocoutinho91
 */
public enum Severity {
    CRITICAL(4, "#ff3b5c"),
    HIGH(3, "#ff8a3d"),
    MEDIUM(2, "#ffd23d"),
    LOW(1, "#3dd6ff"),
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
