package com.securitysite.securitydemosite.security.risk;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.Enumeration;

@Component
public class ParamRiskCalculator implements RiskCalculator {

    @Override
    public RiskScore calculate(HttpServletRequest request) {
        int score = 0;
        StringBuilder reason = new StringBuilder();

        Enumeration<String> names = request.getParameterNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            String value = request.getParameter(name);

            if (value == null) continue;

            // XSS pattern
            if (value.toLowerCase().contains("<script")) {
                score += 40;
                reason.append("XSS payload detected; ");
            }

            // SQLi pattern
            if (value.contains("'") || value.toLowerCase().contains(" or ")) {
                score += 20;
                reason.append("Possible SQL injection; ");
            }

            // Very long param
            if (value.length() > 200) {
                score += 10;
                reason.append("Suspicious long parameter; ");
            }
        }

        return new RiskScore(score, reason.toString());
    }
}
