package com.securitysite.securitydemosite.security;

import com.securitysite.securitydemosite.security.risk.*;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RiskEngineTests {

    private RiskEngine newEngine() {
        return new RiskEngine(
                new ParamRiskCalculator(),
                new HeaderRiskCalculator(),
                new UrlRiskCalculator(),
                new MethodRiskCalculator()
        );
    }

    private Enumeration<String> emptyEnum() {
        return new IteratorEnumeration<>(Collections.<String>emptyList().iterator());
    }

    @Test
    void userAgent_sqlmap_shouldIncreaseRisk() {
        HttpServletRequest req = mock(HttpServletRequest.class);

        when(req.getHeader("User-Agent")).thenReturn("sqlmap/1.0");
        when(req.getRequestURI()).thenReturn("/search");
        when(req.getMethod()).thenReturn("GET");
        when(req.getParameterNames()).thenReturn(emptyEnum());

        RiskEngine engine = newEngine();
        RiskScore score = engine.evaluate(req);

        System.out.println("[RiskEngineTests] userAgent_sqlmap_shouldIncreaseRisk: " + score.value());

        assertThat(score.value()).isGreaterThanOrEqualTo(30);
    }

    @Test
    void longParam_shouldIncreaseRisk() {
        HttpServletRequest req = mock(HttpServletRequest.class);

        when(req.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        when(req.getRequestURI()).thenReturn("/search");
        when(req.getMethod()).thenReturn("GET");

        // параметр q з дуже довгим значенням
        when(req.getParameterNames())
                .thenReturn(new IteratorEnumeration<>(Collections.singletonList("q").iterator()));
        String longValue = "a".repeat(300);
        when(req.getParameter("q")).thenReturn(longValue);

        RiskEngine engine = newEngine();
        RiskScore score = engine.evaluate(req);

        System.out.println("[RiskEngineTests] longParam_shouldIncreaseRisk: " + score.value());

        assertThat(score.value()).isGreaterThanOrEqualTo(10);
    }

    @Test
    void safeRequest_shouldLowRisk() {
        HttpServletRequest req = mock(HttpServletRequest.class);

        when(req.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        when(req.getRequestURI()).thenReturn("/home");
        when(req.getMethod()).thenReturn("GET");
        when(req.getParameterNames()).thenReturn(emptyEnum());

        RiskEngine engine = newEngine();
        RiskScore score = engine.evaluate(req);

        System.out.println("[RiskEngineTests] safeRequest_shouldLowRisk: " + score.value());

        assertThat(score.value()).isLessThan(10);
    }

    /**
     * Технічний helper: обгортає Iterator в Enumeration,
     * щоб Mockito не повертав null.
     */
    private static class IteratorEnumeration<T> implements Enumeration<T> {
        private final Iterator<T> it;

        IteratorEnumeration(Iterator<T> it) {
            this.it = it;
        }

        @Override
        public boolean hasMoreElements() {
            return it.hasNext();
        }

        @Override
        public T nextElement() {
            return it.next();
        }
    }
}
