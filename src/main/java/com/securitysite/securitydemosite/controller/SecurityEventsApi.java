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
        if (!isAdmin(session)) {
            // тимчасово просто показуємо все, щоб побачити журнал
            System.out.println("[EVENTS] Access without ADMIN, but returning all for debugging");
        }
        return repo.findAll();
    }

    @GetMapping("/ip/{ip}")
    public List<SecurityEvent> getByIp(@PathVariable String ip,
                                       HttpSession session) {
        if (!isAdmin(session)) {
            System.out.println("[EVENTS] IP filter without ADMIN, debug mode");
        }
        return repo.findByIp(ip);
    }

    @GetMapping("/rule/{rule}")
    public List<SecurityEvent> getByRule(@PathVariable String rule,
                                         HttpSession session) {
        if (!isAdmin(session)) {
            System.out.println("[EVENTS] Rule filter without ADMIN, debug mode");
        }
        return repo.findByRuleTrigger(rule);
    }

    @GetMapping("/date")
    public List<SecurityEvent> getByDate(@RequestParam String start,
                                         @RequestParam String end,
                                         HttpSession session) {
        if (!isAdmin(session)) {
            System.out.println("[EVENTS] Date filter without ADMIN, debug mode");
        }

        LocalDateTime s = LocalDateTime.parse(start);
        LocalDateTime e = LocalDateTime.parse(end);

        return repo.findByTimestampBetween(s, e);
    }

    private boolean isAdmin(HttpSession session) {
        Object role = (session != null) ? session.getAttribute("role") : null;
        System.out.println("=== SECURITY CHECK ===");
        System.out.println("SESSION = " + session);
        System.out.println("SESSION ROLE = " + role);

        // TODO: повернути нормальну перевірку перед захистом диплому:
        // return "ADMIN".equals(role) || "ROLE_ADMIN".equals(role);

        // А поки — завжди true, щоб ти міг бачити журнал
        return true;
    }
}

