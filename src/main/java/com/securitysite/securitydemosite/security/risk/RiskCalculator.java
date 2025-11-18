package com.securitysite.securitydemosite.security.risk;

import jakarta.servlet.http.HttpServletRequest;

public interface RiskCalculator {
    RiskScore calculate(HttpServletRequest request);
}
