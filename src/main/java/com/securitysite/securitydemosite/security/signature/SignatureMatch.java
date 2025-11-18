package com.securitysite.securitydemosite.security.signature;

public class SignatureMatch {

    private final String ruleId;
    private final AttackType attackType;
    private final String location;
    private final String description;
    private final String sample;

    public SignatureMatch(String ruleId,
                          AttackType attackType,
                          String location,
                          String description,
                          String sample) {
        this.ruleId = ruleId;
        this.attackType = attackType;
        this.location = location;
        this.description = description;
        this.sample = sample;
    }

    public String ruleId() {
        return ruleId;
    }

    public AttackType attackType() {
        return attackType;
    }

    public String location() {
        return location;
    }

    public String description() {
        return description;
    }

    public String sample() {
        return sample;
    }
}
