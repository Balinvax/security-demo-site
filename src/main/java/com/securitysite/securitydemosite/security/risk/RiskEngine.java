package com.securitysite.securitydemosite.security.risk;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RiskEngine {

    private final List<RiskCalculator> calculators;

    public RiskEngine(
            ParamRiskCalculator p,
            HeaderRiskCalculator h,
            UrlRiskCalculator u,
            MethodRiskCalculator m
    ) {
        this.calculators = List.of(p, h, u, m);
    }

    public RiskScore evaluate(HttpServletRequest req) {

        int score = 0;
        StringBuilder reason = new StringBuilder();

        for (RiskCalculator calc : calculators) {
            RiskScore r = calc.calculate(req);
            score += r.value();
            reason.append(r.reason());
        }

        return new RiskScore(score, reason.toString());
    }
}
