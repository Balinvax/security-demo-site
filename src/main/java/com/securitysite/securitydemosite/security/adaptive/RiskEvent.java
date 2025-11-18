package com.securitysite.securitydemosite.adaptive;

public class RiskEvent {

    public int score;
    public boolean anomaly;

    public RiskEvent(int score) {
        this.score = score;
        this.anomaly = score > 0;
    }
}
