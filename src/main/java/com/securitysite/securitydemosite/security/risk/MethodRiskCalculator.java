package com.securitysite.securitydemosite.security.risk;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class MethodRiskCalculator implements RiskCalculator {

    private static final Set<String> ALLOWED = Set.of("GET", "POST");

    @Override
    public RiskScore calculate(HttpServletRequest request) {
        String method = request.getMethod();

        if (!ALLOWED.contains(method)) {
            return new RiskScore(15, "Unexpected HTTP method");
        }

        return new RiskScore(0, "");
    }
}
