package com.securitysite.securitydemosite.security;

import com.securitysite.securitydemosite.security.signature.SignatureEngine;
import com.securitysite.securitydemosite.security.signature.SignatureMatch;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SignatureEngineTests {

    private Enumeration<String> emptyEnum() {
        return new IteratorEnumeration<>(Collections.<String>emptyList().iterator());
    }

    @Test
    void xss_signature_detected() {
        HttpServletRequest req = mock(HttpServletRequest.class);

        when(req.getRequestURI()).thenReturn("/search");
        when(req.getQueryString()).thenReturn("q=<script>alert(1)</script>");

        // параметр q
        when(req.getParameterNames())
                .thenReturn(new IteratorEnumeration<>(Collections.singletonList("q").iterator()));
        when(req.getParameterValues("q"))
                .thenReturn(new String[]{"<script>alert(1)</script>"});

        SignatureEngine engine = new SignatureEngine();
        List<SignatureMatch> matches = engine.analyze(req);

        System.out.println("[SignatureEngineTests] xss_signature_detected: " + matches.size());

        assertThat(matches)
                .anyMatch(m -> m.attackType().name().equals("XSS"));
    }

    @Test
    void sql_signature_detected() {
        HttpServletRequest req = mock(HttpServletRequest.class);

        when(req.getRequestURI()).thenReturn("/search");
        when(req.getQueryString()).thenReturn("id=1 OR 1=1");

        when(req.getParameterNames())
                .thenReturn(new IteratorEnumeration<>(Collections.singletonList("id").iterator()));
        when(req.getParameterValues("id"))
                .thenReturn(new String[]{"1 OR 1=1"});

        SignatureEngine engine = new SignatureEngine();
        List<SignatureMatch> matches = engine.analyze(req);

        System.out.println("[SignatureEngineTests] sql_signature_detected: " + matches.size());

        assertThat(matches)
                .anyMatch(m -> m.attackType().name().equals("SQL_INJECTION"));
    }

    /**
     * Helper для перетворення Iterator -> Enumeration
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
