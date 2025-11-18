package com.securitysite.securitydemosite.security;

public class SignatureMatch {

    private final String ruleId;
    private final AttackType attackType;
    private final String location;    // PATH, QUERY, PARAM:name, HEADER:User-Agent, ...
    private final String description; // короткий опис правила
    private final String valueSample; // фрагмент значення, де знайдено збіг

    public SignatureMatch(String ruleId,
                          AttackType attackType,
                          String location,
                          String description,
                          String valueSample) {
        this.ruleId = ruleId;
        this.attackType = attackType;
        this.location = location;
        this.description = description;
        this.valueSample = valueSample;
    }

    public String getRuleId() {
        return ruleId;
    }

    public AttackType getAttackType() {
        return attackType;
    }

    public String getLocation() {
        return location;
    }

    public String getDescription() {
        return description;
    }

    public String getValueSample() {
        return valueSample;
    }

    @Override
    public String toString() {
        return "SignatureMatch{" +
                "ruleId='" + ruleId + '\'' +
                ", attackType=" + attackType +
                ", location='" + location + '\'' +
                ", description='" + description + '\'' +
                ", valueSample='" + valueSample + '\'' +
                '}';
    }
}
