package com.securitysite.securitydemosite.security.risk;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class UrlRiskCalculator implements RiskCalculator {

    @Override
    public RiskScore calculate(HttpServletRequest request) {
        String path = request.getRequestURI().toLowerCase();

        if (path.contains("select") || path.contains("union") || path.contains("etc/passwd")) {
            return new RiskScore(50, "Dangerous URL pattern detected");
        }

        return new RiskScore(0, "");
    }
}
