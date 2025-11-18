package com.securitysite.securitydemosite.security.signature;

import java.util.regex.Pattern;

class SignatureRule {

    private final String id;
    private final AttackType type;
    private final Pattern pattern;
    private final String description;

    public SignatureRule(String id,
                         AttackType type,
                         Pattern pattern,
                         String description) {
        this.id = id;
        this.type = type;
        this.pattern = pattern;
        this.description = description;
    }

    public String getId() {
        return id;
    }

    public AttackType getType() {
        return type;
    }

    public Pattern getPattern() {
        return pattern;
    }

    public String getDescription() {
        return description;
    }
}
