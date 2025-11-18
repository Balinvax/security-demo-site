package com.securitysite.securitydemosite.controller;

import com.securitysite.securitydemosite.model.SecurityEvent;
import com.securitysite.securitydemosite.repository.SecurityEventRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/admin/events")
public class SecurityEventsApi {

    private final SecurityEventRepository repo;

    public SecurityEventsApi(SecurityEventRepository repo) {
        this.repo = repo;
    }

    @GetMapping
    public List<SecurityEvent> getAll(HttpSession session) {
        if (!isAdmin(session)) return List.of();
        return repo.findAll();
    }

    @GetMapping("/ip/{ip}")
    public List<SecurityEvent> getByIp(@PathVariable String ip,
                                       HttpSession session) {
        if (!isAdmin(session)) return List.of();
        return repo.findByIp(ip);
    }

    @GetMapping("/rule/{rule}")
    public List<SecurityEvent> getByRule(@PathVariable String rule,
                                         HttpSession session) {
        if (!isAdmin(session)) return List.of();
        return repo.findByRuleTrigger(rule);
    }

    @GetMapping("/date")
    public List<SecurityEvent> getByDate(@RequestParam String start,
                                         @RequestParam String end,
                                         HttpSession session) {
        if (!isAdmin(session)) return List.of();

        LocalDateTime s = LocalDateTime.parse(start);
        LocalDateTime e = LocalDateTime.parse(end);

        return repo.findByTimestampBetween(s, e);
    }

    private boolean isAdmin(HttpSession session) {
        return "ADMIN".equals(session.getAttribute("role"));
    }
}
