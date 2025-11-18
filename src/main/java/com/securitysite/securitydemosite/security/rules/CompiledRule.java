package com.securitysite.securitydemosite.security.rules;

public class CompiledRule {

    private final String name;
    private final String condition;

    public CompiledRule(String name, String condition) {
        this.name = name;
        this.condition = condition;
    }

    public String getName() {
        return name;
    }

    public String getCondition() {
        return condition;
    }
}
