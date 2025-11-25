package com.securitysite.securitydemosite.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class IntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    /**
     * 1) Перевірка що звичайний запит дозволений.
     */
    @Test
    void allowed_request_should_pass() throws Exception {

        mockMvc.perform(
                        get("/?q=hello")
                                .header("User-Agent", "Mozilla/5.0")  // обов’язково!
                )
                .andExpect(status().isOk());

        System.out.println("\n[IntegrationTests] ✔ allowed_request_should_pass — PASSED\n");
    }

    /**
     * 2) Перевірка XSS блокування.
     */
    @Test
    void xss_should_be_blocked() throws Exception {

        mockMvc.perform(
                        get("/?q=<script>alert(1)</script>")
                                .header("User-Agent", "Mozilla/5.0")
                )
                .andExpect(status().isForbidden());

        System.out.println("\n[IntegrationTests] ✔ xss_should_be_blocked — PASSED\n");
    }

    /**
     * 3) Перевірка SQL injection блокування.
     */
    @Test
    void sql_injection_should_be_blocked() throws Exception {

        mockMvc.perform(
                        get("/?id=1 OR 1=1")
                                .header("User-Agent", "Mozilla/5.0")
                )
                .andExpect(status().isForbidden());

        System.out.println("\n[IntegrationTests] ✔ sql_injection_should_be_blocked — PASSED\n");
    }
}
