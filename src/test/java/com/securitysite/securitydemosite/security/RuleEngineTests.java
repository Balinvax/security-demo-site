package com.securitysite.securitydemosite.security;

import com.securitysite.securitydemosite.security.rules.*;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class RuleEngineTests {

    @Test
    void rule_contains_should_trigger() {
        RuleParser parser = new RuleParser();
        RuleEngine engine = parser.parse("""
            RULE XSS IF param CONTAINS "<script"
        """);

        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        Mockito.when(req.getQueryString()).thenReturn("q=<script>alert(1)</script>");

        List<String> result = engine.evaluate(req, Map.of());
        assertTrue(result.contains("XSS"));

        System.out.println("✔ RuleEngineTests: CONTAINS rule test passed");
    }

    @Test
    void rule_role_should_trigger() {
        RuleParser parser = new RuleParser();
        RuleEngine engine = parser.parse("""
            RULE BLOCK_NON_ADMIN IF role != "ADMIN"
        """);

        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        Map<String, Object> ctx = Map.of("role", "USER");

        List<String> result = engine.evaluate(req, ctx);
        assertTrue(result.contains("BLOCK_NON_ADMIN"));

        System.out.println("✔ RuleEngineTests: role != ADMIN test passed");
    }
}
