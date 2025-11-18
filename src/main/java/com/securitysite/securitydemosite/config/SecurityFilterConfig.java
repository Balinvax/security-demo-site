package com.securitysite.securitydemosite.config;

import com.securitysite.securitydemosite.security.filter.SecurityFilter;

import com.securitysite.securitydemosite.security.risk.RiskEngine;
import com.securitysite.securitydemosite.security.risk.RiskCalculator;
import com.securitysite.securitydemosite.security.risk.ParamRiskCalculator;
import com.securitysite.securitydemosite.security.risk.HeaderRiskCalculator;
import com.securitysite.securitydemosite.security.risk.UrlRiskCalculator;
import com.securitysite.securitydemosite.security.risk.MethodRiskCalculator;

import com.securitysite.securitydemosite.security.adaptive.AdaptiveEngine;
import com.securitysite.securitydemosite.security.adaptive.MovingWindow;
import com.securitysite.securitydemosite.security.adaptive.AnomalyDetector;

import com.securitysite.securitydemosite.security.signature.SignatureEngine;

import com.securitysite.securitydemosite.security.rules.RuleEngine;
import com.securitysite.securitydemosite.security.rules.RuleParser;

import com.securitysite.securitydemosite.security.traffic.RateLimiter;
import com.securitysite.securitydemosite.security.traffic.ScannerDetector;
import com.securitysite.securitydemosite.security.traffic.AntiBotRules;
import com.securitysite.securitydemosite.security.traffic.TrafficAnalyzer;

import com.securitysite.securitydemosite.service.SecurityLogService;

import jakarta.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

@Configuration
public class SecurityFilterConfig {

    // =========================
    // 1. RISK ENGINE
    // =========================
    @Bean
    public RiskEngine riskEngine() {
        return new RiskEngine(
                new ParamRiskCalculator(),
                new HeaderRiskCalculator(),
                new UrlRiskCalculator(),
                new MethodRiskCalculator()
        );
    }

    // =========================
    // 2. ADAPTIVE ENGINE
    // =========================
    @Bean
    public AdaptiveEngine adaptiveEngine() {
        return new AdaptiveEngine(
                new MovingWindow(1000),
                new AnomalyDetector()
        );
    }

    // =========================
    // 3. SIGNATURE ENGINE
    // =========================
    @Bean
    public SignatureEngine signatureEngine() {
        return new SignatureEngine();
    }

    // =========================
    // 4. RULE ENGINE (DSL)
    // =========================
    @Bean
    public RuleEngine ruleEngine() {
        RuleParser parser = new RuleParser();

        // Тестові правила — ти можеш додавати свої
        String rules = """
            RULE BLOCK_XSS IF param CONTAINS "<script"
            RULE BLOCK_SQLI IF param CONTAINS "select "
            RULE LIMIT_RATE IF ip.req_per_min > 50
            RULE BLOCK_METHOD IF method NOT IN [GET, POST]
        """;

        return parser.parse(rules);
    }

    // =========================
    // 5. RATE LIMIT + ANTI-SCANNER
    // =========================
    @Bean
    public RateLimiter rateLimiter() {
        return new RateLimiter(60); // 60 req/min
    }

    @Bean
    public ScannerDetector scannerDetector() {
        return new ScannerDetector();
    }

    @Bean
    public AntiBotRules antiBotRules() {
        return new AntiBotRules();
    }

    @Bean
    public TrafficAnalyzer trafficAnalyzer() {
        return new TrafficAnalyzer(scannerDetector(), antiBotRules());
    }

    // =========================
    // 6. SECURITY FILTER
    // =========================
    @Bean
    public SecurityFilter securityFilter(
            RiskEngine riskEngine,
            AdaptiveEngine adaptiveEngine,
            SignatureEngine signatureEngine,
            RuleEngine ruleEngine,
            RateLimiter rateLimiter,
            TrafficAnalyzer trafficAnalyzer,
            SecurityLogService logService
    ) {
        return new SecurityFilter(
                riskEngine,
                adaptiveEngine,
                signatureEngine,
                ruleEngine,
                rateLimiter,
                trafficAnalyzer,
                logService
        );
    }

    // =========================
    // 7. FILTER REGISTRATION
    // =========================
    @Bean
    public FilterRegistrationBean<Filter> filterRegistration(SecurityFilter filter) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();

        bean.setFilter(filter);
        bean.addUrlPatterns("/*");
        bean.setOrder(1); // фільтр №1, йде перед усіма контролерами

        return bean;
    }
}
