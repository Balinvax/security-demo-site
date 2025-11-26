package com.securitysite.securitydemosite.controller;

import com.securitysite.securitydemosite.model.SecurityEvent;
import com.securitysite.securitydemosite.repository.SecurityEventRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;

@RestController
@RequestMapping("/api/admin/events")
public class SecurityEventsApi {

    private final SecurityEventRepository repo;

    public SecurityEventsApi(SecurityEventRepository repo) {
        this.repo = repo;
    }


    private boolean isAdmin(HttpSession session) {


        if (session == null) {

            return false;
        }

        Object role = session.getAttribute("role");


        if (role == null) return false;

        String r = role.toString();
        // покриваємо варіанти "ADMIN", "ROLE_ADMIN", "ROLE_ADMIN,ROLE_USER" і т.п.
        return r.equals("ADMIN")
                || r.equals("ROLE_ADMIN")
                || r.contains("ADMIN");
    }

    // ====== Ендпоїнти ======

    @GetMapping
    public List<SecurityEvent> getAll(HttpSession session) {
        if (!isAdmin(session)) return List.of();
        // можеш замінити на findAllByOrderByTimestampDesc(), якщо додаси в репозиторій
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

        LocalDateTime s = parseClientDateTime(start);
        LocalDateTime e = parseClientDateTime(end);

        if (s == null || e == null) {
            System.out.println("BAD DATE RANGE: start=" + start + ", end=" + end);
            return List.of();
        }

        return repo.findByTimestampBetween(s, e);
    }

    private LocalDateTime parseClientDateTime(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        try {
            return LocalDateTime.parse(value);
        } catch (DateTimeParseException ex) {
            try {
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm");
                return LocalDateTime.parse(value, formatter);
            } catch (DateTimeParseException ex2) {
                System.out.println("Failed to parse datetime: " + value +
                        " | " + ex2.getMessage());
                return null;
            }
        }
    }
}
