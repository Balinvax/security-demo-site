package com.securitysite.securitydemosite.config;

import com.securitysite.securitydemosite.security.adaptive.AdaptiveEngine;
import com.securitysite.securitydemosite.security.filter.SecurityFilter;
import com.securitysite.securitydemosite.security.risk.RiskEngine;
import com.securitysite.securitydemosite.security.rules.RuleEngine;
import com.securitysite.securitydemosite.security.rules.RuleParser;
import com.securitysite.securitydemosite.security.signature.SignatureEngine;
import com.securitysite.securitydemosite.security.traffic.AntiBotRules;
import com.securitysite.securitydemosite.security.traffic.RateLimiter;
import com.securitysite.securitydemosite.security.traffic.ScannerDetector;
import com.securitysite.securitydemosite.security.traffic.TrafficAnalyzer;
import com.securitysite.securitydemosite.service.SecurityLogService;
import jakarta.servlet.Filter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityFilterConfig {

    // =======================
    // 1. Adaptive Engine
    // =======================
    @Bean
    public AdaptiveEngine adaptiveEngine() {
        return new AdaptiveEngine();
    }

    // =======================
    // 2. Signature Engine
    // =======================
    @Bean
    public SignatureEngine signatureEngine() {
        return new SignatureEngine();
    }

    // =======================
    // 3. Rule Engine
    // =======================
    @Bean
    public RuleEngine ruleEngine() {
        RuleParser parser = new RuleParser();

        String rules = """
                    RULE BLOCK_XSS IF param CONTAINS "<script"
                    RULE BLOCK_SQLI IF param CONTAINS "select "
                    RULE LIMIT_RATE IF ip.req_per_min > 50
                    RULE BLOCK_METHOD IF method NOT IN [GET, POST]
                """;

        return parser.parse(rules); // ← правильне використання
    }

    // =======================
    // 4. Traffic Analyzer
    // =======================
    @Bean
    public RateLimiter rateLimiter() {
        return new RateLimiter();
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
    public TrafficAnalyzer trafficAnalyzer(
            RateLimiter rateLimiter,
            ScannerDetector scannerDetector,
            AntiBotRules antiBotRules
    ) {
        return new TrafficAnalyzer(rateLimiter, scannerDetector, antiBotRules);
    }

    // =======================
    // 5. Security Filter
    // =======================
    @Bean
    public SecurityFilter securityFilter(
            RiskEngine riskEngine,
            AdaptiveEngine adaptiveEngine,
            SignatureEngine signatureEngine,
            RuleEngine ruleEngine,
            TrafficAnalyzer trafficAnalyzer,
            SecurityLogService logService
    ) {
        return new SecurityFilter(
                riskEngine,
                adaptiveEngine,
                signatureEngine,
                ruleEngine,
                trafficAnalyzer,
                logService
        );
    }

    // =======================
    // 6. Filter registration
    // =======================
    @Bean
    public FilterRegistrationBean<Filter> filterRegistration(SecurityFilter filter) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();

        bean.setFilter(filter);
        bean.addUrlPatterns("/*");
        bean.setOrder(1);

        return bean;
    }
}
