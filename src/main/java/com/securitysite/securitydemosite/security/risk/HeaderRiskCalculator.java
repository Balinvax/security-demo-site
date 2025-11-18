package com.securitysite.securitydemosite.security.risk;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class HeaderRiskCalculator implements RiskCalculator {

    @Override
    public RiskScore calculate(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        if (ua == null) return new RiskScore(0, "");

        ua = ua.toLowerCase();

        if (ua.contains("sqlmap") || ua.contains("nmap") || ua.contains("curl")) {
            return new RiskScore(30, "Suspicious User-Agent");
        }

        return new RiskScore(0, "");
    }
}
