package com.securitysite.securitydemosite.security.filter;

import com.securitysite.securitydemosite.security.risk.RiskEngine;
import com.securitysite.securitydemosite.security.adaptive.AdaptiveEngine;
import com.securitysite.securitydemosite.security.signature.SignatureEngine;
import com.securitysite.securitydemosite.security.rules.RuleEngine;
import com.securitysite.securitydemosite.security.traffic.RateLimiter;
import com.securitysite.securitydemosite.security.traffic.TrafficAnalyzer;
import com.securitysite.securitydemosite.service.SecurityLogService;
import com.securitysite.securitydemosite.security.signature.AttackType;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

public class SecurityFilter implements Filter {git

    private final RiskEngine riskEngine;
    private final AdaptiveEngine adaptiveEngine;
    private final SignatureEngine signatureEngine;
    private final RuleEngine ruleEngine;

    private final RateLimiter rateLimiter;
    private final TrafficAnalyzer trafficAnalyzer;

    private final SecurityLogService logService;

    public SecurityFilter(
            RiskEngine riskEngine,
            AdaptiveEngine adaptiveEngine,
            SignatureEngine signatureEngine,
            RuleEngine ruleEngine,
            RateLimiter rateLimiter,
            TrafficAnalyzer trafficAnalyzer,
            SecurityLogService logService
    ) {
        this.riskEngine = riskEngine;
        this.adaptiveEngine = adaptiveEngine;
        this.signatureEngine = signatureEngine;
        this.ruleEngine = ruleEngine;
        this.rateLimiter = rateLimiter;
        this.trafficAnalyzer = trafficAnalyzer;
        this.logService = logService;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String ip = request.getRemoteAddr();
        String method = request.getMethod();
        String path = request.getRequestURI();
        Map<String, String[]> params = request.getParameterMap();
        String userAgent = request.getHeader("User-Agent");

        long timestamp = System.currentTimeMillis();

        /*
         * 1. RPS / RateLimit / Anti-Scanner
         *    Якщо перевищено — блокуємо одразу
         */
        if (!rateLimiter.allow(ip)) {
            logService.log(ip, method, path, params, 0, "RATE_LIMIT", "BLOCK");
            response.setStatus(429);
            response.getWriter().write("Too many requests");
            return;
        }

        if (trafficAnalyzer.isScanner(ip, path)) {
            logService.log(ip, method, path, params, 50, "SCANNER_DETECTED", "BLOCK");
            response.setStatus(403);
            response.getWriter().write("Scanner detected");
            return;
        }

        /*
         * 2. Підрахунок ризику
         */
        int riskScore = riskEngine.calculate(method, path, params, request.getHeaderNames(), request);

        /*
         * 3. Адаптивний аналіз поведінки
         */
        int adaptiveScore = adaptiveEngine.analyze(ip, method, path, params, userAgent);
        riskScore += adaptiveScore;

        /*
         * 4. Сигнатурний аналіз (XSS, SQLi, RCE)
         */
        AttackType attack = signatureEngine.check(path, params, userAgent);
        if (attack != AttackType.NONE) {
            logService.log(ip, method, path, params, 80, attack.name(), "BLOCK");
            response.setStatus(403);
            response.getWriter().write("Blocked by signature rule: " + attack);
            return;
        }

        /*
         * 5. Rule DSL Engine
         */
        String ruleDecision = ruleEngine.evaluate(ip, method, path, params);
        if (!ruleDecision.equals("ALLOW")) {
            logService.log(ip, method, path, params, riskScore, "RULE:" + ruleDecision, "BLOCK");
            response.setStatus(403);
            response.getWriter().write("Request blocked by rule: " + ruleDecision);
            return;
        }

        /*
         * 6. Фінальне рішення на основі ризику
         */
        if (riskScore >= 70) {
            logService.log(ip, method, path, params, riskScore, "RISK_ENGINE", "BLOCK");
            response.setStatus(403);
            response.getWriter().write("Blocked by risk engine");
            return;
        }

        /*
         * 7. Логування дозволеного запиту
         */
        logService.log(ip, method, path, params, riskScore, "OK", "ALLOW");

        /*
         * 8. Пропускаємо далі
         */
        chain.doFilter(request, response);
    }
}
