package com.securitysite.securitydemosite.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue
    private UUID id;

    private LocalDateTime timestamp;

    private String ip;
    private String method;
    private String path;

    @Column(columnDefinition = "TEXT")
    private String params;

    private String ruleTrigger;
    private int riskScore;
    private String decision;

    public SecurityEvent() {}

    @PrePersist
    public void onCreate() {
        timestamp = LocalDateTime.now();
    }

    // getters + setters
}
