package com.securitysite.securitydemosite.security.risk;

public class RiskScore {

    private final int value;
    private final String reason;

    public RiskScore(int value, String reason) {
        this.value = value;
        this.reason = reason;
    }

    public int value() {
        return value;
    }

    public String reason() {
        return reason;
    }
}
