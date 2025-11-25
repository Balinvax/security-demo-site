package com.securitysite.securitydemosite.security;

import com.securitysite.securitydemosite.security.traffic.AntiBotRules;
import com.securitysite.securitydemosite.security.traffic.RateLimiter;
import com.securitysite.securitydemosite.security.traffic.ScannerDetector;
import com.securitysite.securitydemosite.security.traffic.TrafficAnalyzer;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TrafficAnalyzerTests {

    private TrafficAnalyzer newAnalyzer() {
        return new TrafficAnalyzer(
                new RateLimiter(),
                new ScannerDetector(),
                new AntiBotRules()
        );
    }

    @Test
    void bad_user_agent_detected() {
        HttpServletRequest req = mock(HttpServletRequest.class);

        when(req.getRemoteAddr()).thenReturn("127.0.0.1");
        when(req.getMethod()).thenReturn("GET");
        when(req.getHeader("User-Agent")).thenReturn("sqlmap/1.0");

        TrafficAnalyzer analyzer = newAnalyzer();
        List<String> alerts = analyzer.analyze(req, 200);

        System.out.println("[TrafficAnalyzerTests] bad_user_agent_detected: " + alerts);

        assertThat(alerts).contains("BAD_USER_AGENT");
    }

    @Test
    void missing_user_agent_detected() {
        HttpServletRequest req = mock(HttpServletRequest.class);

        when(req.getRemoteAddr()).thenReturn("127.0.0.1");
        when(req.getMethod()).thenReturn("GET");
        when(req.getHeader("User-Agent")).thenReturn(null);

        TrafficAnalyzer analyzer = newAnalyzer();
        List<String> alerts = analyzer.analyze(req, 200);

        System.out.println("[TrafficAnalyzerTests] missing_user_agent_detected: " + alerts);

        assertThat(alerts).contains("NO_USER_AGENT");
    }
}
