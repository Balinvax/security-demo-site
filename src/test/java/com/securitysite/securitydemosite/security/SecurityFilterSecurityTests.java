package com.securitysite.securitydemosite.security;

import com.securitysite.securitydemosite.security.filter.SecurityFilter;
import com.securitysite.securitydemosite.service.SecurityLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityFilterSecurityTests {

    @Autowired
    private MockMvc mockMvc;

    // Ми МОКУЄМО лог-сервіс, щоб не писав у БД
    @MockBean
    private SecurityLogService logService;

    @BeforeEach
    void disableSecurityLogging() {
        // просто не робимо нічого в мок-методі
        Mockito.doNothing().when(logService)
                .log(Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any(), Mockito.anyMap());
    }

    // =====================================================
    // 1. Звичайний запит — має пройти (200)
    // =====================================================
    @Test
    void homePage_shouldBeAccessible() throws Exception {
        mockMvc.perform(get("/")
                        .header("User-Agent", "Mozilla"))       // <-- UA передаємо обов'язково!
                .andExpect(status().isOk());
    }

    // =====================================================
    // 2. XSS — SignatureEngine повинен заблокувати (403)
    // =====================================================
    @Test
    void xssPayload_shouldBeBlocked() throws Exception {
        mockMvc.perform(get("/")
                        .header("User-Agent", "Mozilla")
                        .param("q", "<script>alert('XSS')</script>"))
                .andExpect(status().isForbidden());
    }

    // =====================================================
    // 3. SQLi — SignatureEngine повинен заблокувати (403)
    // =====================================================
    @Test
    void sqlInjectionPayload_shouldBeBlocked() throws Exception {
        mockMvc.perform(get("/")
                        .header("User-Agent", "Mozilla")
                        .param("id", "1 OR 1=1"))
                .andExpect(status().isForbidden());
    }
}
