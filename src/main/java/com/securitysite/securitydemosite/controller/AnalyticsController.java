package com.securitysite.securitydemosite.controller;

import com.securitysite.securitydemosite.repository.SecurityEventRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/analytics")
public class AnalyticsController {

    private final SecurityEventRepository repo;

    public AnalyticsController(SecurityEventRepository repo) {
        this.repo = repo;
    }

    private boolean isAdmin(HttpSession session) {
        System.out.println("=== SECURITY CHECK (analytics) ===");
        System.out.println("SESSION = " + session);

        if (session == null) {
            System.out.println("SESSION == null");
            return true; // тимчасово відкрито
        }

        Object role = session.getAttribute("role");
        System.out.println("SESSION ROLE = " + role);

        Object userId = session.getAttribute(AuthController.SESSION_USER_ID);
        System.out.println("SESSION USER_ID = " + userId);

        // тимчасово достатньо, щоб користувач був залогінений
        return userId != null;
    }

    @GetMapping("/rules")
    public Map<String, Long> attacksByRule(HttpSession session) {
        if (!isAdmin(session)) return Map.of();
        return repo.findAll().stream()
                .collect(Collectors.groupingBy(
                        e -> Optional.ofNullable(e.getRuleTrigger()).orElse("UNKNOWN"),
                        Collectors.counting()
                ));
    }

    @GetMapping("/paths")
    public Map<String, Long> popularPaths(HttpSession session) {
        if (!isAdmin(session)) return Map.of();
        return repo.findAll().stream()
                .collect(Collectors.groupingBy(
                        e -> Optional.ofNullable(e.getPath()).orElse("/unknown"),
                        Collectors.counting()
                ));
    }

    @GetMapping("/ip")
    public List<Map.Entry<String, Long>> dangerousIPs(HttpSession session) {
        if (!isAdmin(session)) return List.of();

        Map<String, Long> ipMap = repo.findAll().stream()
                .collect(Collectors.groupingBy(e -> e.getIp(), Collectors.counting()));

        return ipMap.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .toList();
    }

    @GetMapping("/hours")
    public Map<Integer, Long> activityByHour(HttpSession session) {
        if (!isAdmin(session)) return Map.of();

        return repo.findAll().stream()
                .collect(Collectors.groupingBy(
                        e -> e.getTimestamp().getHour(),
                        Collectors.counting()
                ));
    }

    @GetMapping("/heatmap")
    public Map<Integer, Map<Integer, Long>> heatmap(HttpSession session) {
        if (!isAdmin(session)) return Map.of();

        Map<Integer, Map<Integer, Long>> map = new HashMap<>();

        repo.findAll().forEach(e -> {
            int day = e.getTimestamp().getDayOfWeek().getValue(); // 1..7
            int hour = e.getTimestamp().getHour();

            map.putIfAbsent(day, new HashMap<>());
            map.get(day).merge(hour, 1L, Long::sum);
        });

        return map;
    }

    @GetMapping("/risk")
    public Map<String, Object> riskStats(HttpSession session) {
        if (!isAdmin(session)) return Map.of();

        var events = repo.findAll();
        if (events.isEmpty()) return Map.of();

        int min = events.stream().mapToInt(e -> e.getRiskScore()).min().orElse(0);
        int max = events.stream().mapToInt(e -> e.getRiskScore()).max().orElse(0);
        double avg = events.stream().mapToInt(e -> e.getRiskScore()).average().orElse(0.0);

        return Map.of(
                "min", min,
                "max", max,
                "avg", avg
        );
    }
}


