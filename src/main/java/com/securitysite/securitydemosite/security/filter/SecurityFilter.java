package com.securitysite.securitydemosite.security.filter;

import com.securitysite.securitydemosite.security.adaptive.AdaptiveEngine;
import com.securitysite.securitydemosite.security.adaptive.RiskEvent;
import com.securitysite.securitydemosite.security.risk.RiskEngine;
import com.securitysite.securitydemosite.security.risk.RiskScore;
import com.securitysite.securitydemosite.security.rules.RuleEngine;
import com.securitysite.securitydemosite.security.signature.SignatureEngine;
import com.securitysite.securitydemosite.security.signature.SignatureMatch;
import com.securitysite.securitydemosite.security.traffic.TrafficAnalyzer;
import com.securitysite.securitydemosite.service.SecurityLogService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SecurityFilter implements Filter {

    private final RiskEngine riskEngine;
    private final AdaptiveEngine adaptiveEngine;
    private final SignatureEngine signatureEngine;
    private final RuleEngine ruleEngine;
    private final TrafficAnalyzer trafficAnalyzer;
    private final SecurityLogService logService;

    public SecurityFilter(
            RiskEngine riskEngine,
            AdaptiveEngine adaptiveEngine,
            SignatureEngine signatureEngine,
            RuleEngine ruleEngine,
            TrafficAnalyzer trafficAnalyzer,
            SecurityLogService logService
    ) {
        this.riskEngine = riskEngine;
        this.adaptiveEngine = adaptiveEngine;
        this.signatureEngine = signatureEngine;
        this.ruleEngine = ruleEngine;
        this.trafficAnalyzer = trafficAnalyzer;
        this.logService = logService;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        SecurityResponseWrapper response = new SecurityResponseWrapper((HttpServletResponse) res);

        String ip = request.getRemoteAddr();
        String method = request.getMethod();
        String path = request.getRequestURI();
        Map<String, String[]> params = request.getParameterMap();

        // =========================
        // 1. Попередній аналіз трафіку (rate-limit, POST flood, User-Agent)
        // =========================
        List<String> preAlerts = trafficAnalyzer.analyze(request, 0);
        if (!preAlerts.isEmpty()) {
            // серйозні алерти -> одразу блокуємо
            if (preAlerts.contains("RATE_LIMIT_EXCEEDED")
                    || preAlerts.contains("POST_FLOOD_DETECTED")
                    || preAlerts.contains("BAD_USER_AGENT")) {

                int riskScore = 80;
                logService.log(request,
                        String.join(",", preAlerts),
                        riskScore,
                        "BLOCK",
                        params);

                response.setStatus(429);
                response.getWriter().write("Request blocked by traffic policy");
                return;
            }
        }

        // =========================
        // 2. Risk Engine
        // =========================
        RiskScore baseRisk = riskEngine.evaluate(request);
        int riskScore = baseRisk.value();

        // =========================
        // 3. Adaptive Engine
        // (поки без реального payloadSize і statusCode — ставимо 0 та 200)
        // =========================
        RiskEvent adaptive = adaptiveEngine.process(request, 0, 200);
        riskScore += adaptive.score;

        // =========================
        // 4. Signature Engine (XSS, SQLi, Path Traversal ...)
        // =========================
        List<SignatureMatch> matches = signatureEngine.analyze(request);
        if (!matches.isEmpty()) {
            SignatureMatch m = matches.get(0);
            String ruleName = "SIG:" + m.attackType().name() + ":" + m.ruleId();

            logService.log(request,
                    ruleName,
                    90,
                    "BLOCK",
                    params);

            response.setStatus(403);
            response.getWriter().write("Blocked by signature rule");
            return;
        }

        // =========================
        // 5. Rule DSL Engine
        // =========================
        Map<String, Object> ctx = new HashMap<>();
        // роль з сесії (для правил типу role != "ADMIN")
        if (request.getSession(false) != null) {
            Object role = request.getSession(false).getAttribute("role");
            if (role != null) {
                ctx.put("role", role.toString());
            }
        }

        List<String> triggeredRules = ruleEngine.evaluate(request, ctx);
        if (!triggeredRules.isEmpty()) {
            logService.log(request,
                    "RULE:" + String.join(",", triggeredRules),
                    riskScore,
                    "BLOCK",
                    params);

            response.setStatus(403);
            response.getWriter().write("Request blocked by rule engine");
            return;
        }

        // =========================
        // 6. Поріг ризику
        // =========================
        if (riskScore >= 70) {
            logService.log(request,
                    "RISK_ENGINE",
                    riskScore,
                    "BLOCK",
                    params);

            response.setStatus(403);
            response.getWriter().write("Blocked by risk engine");
            return;
        }

        // =========================
        // 7. Логування дозволеного запиту
        // =========================
        logService.log(request,
                "OK",
                riskScore,
                "ALLOW",
                params);

        // =========================
        // 8. Пропускаємо запит далі
        // =========================
        chain.doFilter(request, response);

        // =========================
        // 9. Постфактум аналіз (404 → scanner, UA тощо)
        // =========================
        int statusCode = response.getStatus();
        trafficAnalyzer.analyze(request, statusCode);
    }

    /**
     * Обгортка для збереження HTTP статусу відповіді.
     */
    private static class SecurityResponseWrapper extends HttpServletResponseWrapper {

        private int httpStatus = SC_OK;

        public SecurityResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void setStatus(int sc) {
            super.setStatus(sc);
            this.httpStatus = sc;
        }

        @Override
        public void sendError(int sc) throws IOException {
            super.sendError(sc);
            this.httpStatus = sc;
        }

        @Override
        public void sendError(int sc, String msg) throws IOException {
            super.sendError(sc, msg);
            this.httpStatus = sc;
        }

        @Override
        public void sendRedirect(String location) throws IOException {
            super.sendRedirect(location);
            this.httpStatus = SC_FOUND;
        }

        public int getStatus() {
            return httpStatus;
        }
    }
}
