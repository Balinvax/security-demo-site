package com.securitysite.securitydemosite.repository;

import com.securitysite.securitydemosite.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    List<SecurityEvent> findByIp(String ip);
    List<SecurityEvent> findByRuleTrigger(String ruleTrigger);
    List<SecurityEvent> findByTimestampBetween(LocalDateTime start, LocalDateTime end);
}
