package com.securitysite.securitydemosite.security;

import com.securitysite.securitydemosite.model.SecurityEvent;
import com.securitysite.securitydemosite.repository.SecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class AnalyticsTests {

    @Autowired
    SecurityEventRepository repo;

    @Test
    void should_store_event() {
        SecurityEvent ev = new SecurityEvent();
        ev.setIp("1.2.3.4");
        ev.setMethod("GET");
        ev.setPath("/");
        ev.setRuleTrigger("TEST_RULE");
        ev.setRiskScore(50);
        ev.setDecision("BLOCK");
        ev.setParams("{}");

        repo.save(ev);

        assertFalse(repo.findByIp("1.2.3.4").isEmpty());

        System.out.println("✔ AnalyticsTests: event stored test passed");
    }

    @Test
    void should_find_by_rule() {
        List<SecurityEvent> list = repo.findByRuleTrigger("TEST_RULE");
        assertFalse(list.isEmpty());

        System.out.println("✔ AnalyticsTests: find by rule test passed");
    }

    @Test
    void should_find_by_date_range() {
        LocalDateTime now = LocalDateTime.now();

        List<SecurityEvent> list =
                repo.findByTimestampBetween(now.minusDays(1), now.plusDays(1));

        assertFalse(list.isEmpty());

        System.out.println("✔ AnalyticsTests: date range test passed");
    }
}
