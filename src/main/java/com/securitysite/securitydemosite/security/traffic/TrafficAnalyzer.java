package com.securitysite.securitydemosite.security;

import com.securitysite.securitydemosite.security.rate.RateLimiter;
import com.securitysite.securitydemosite.security.scanner.ScannerDetector;
import com.securitysite.securitydemosite.security.bot.AntiBotRules;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

public class TrafficAnalyzer {

    private final RateLimiter rateLimiter = new RateLimiter();
    private final ScannerDetector scannerDetector = new ScannerDetector();
    private final AntiBotRules botRules = new AntiBotRules();

    public List<String> analyze(HttpServletRequest req, int statusCode) {

        List<String> alerts = new ArrayList<>();
        String ip = req.getRemoteAddr();

        // Rate limiting
        if (rateLimiter.isRateExceeded(ip)) {
            alerts.add("RATE_LIMIT_EXCEEDED");
        }

        // POST flood
        if ("POST".equalsIgnoreCase(req.getMethod())
                && rateLimiter.isPostFlood(ip)) {
            alerts.add("POST_FLOOD_DETECTED");
        }

        // Scanner detection by 404
        if (statusCode == 404) {
            scannerDetector.record404(ip);
        }
        if (scannerDetector.isScanner(ip)) {
            alerts.add("SCANNER_DETECTED");
        }

        // User-Agent bad signatures
        if (botRules.isBadUserAgent(req)) {
            alerts.add("BAD_USER_AGENT");
        }

        // Missing UA
        if (botRules.missingUA(req)) {
            alerts.add("NO_USER_AGENT");
        }

        return alerts;
    }
}
