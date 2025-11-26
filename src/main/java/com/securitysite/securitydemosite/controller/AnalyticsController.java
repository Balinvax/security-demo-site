package com.securitysite.securitydemosite.controller;

import com.securitysite.securitydemosite.repository.SecurityEventRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/analytics")
public class AnalyticsController {

    private final SecurityEventRepository repo;

    public AnalyticsController(SecurityEventRepository repo) {
        this.repo = repo;
    }

    // Уніфікована перевірка адміна, як у SecurityEventsApi
    private boolean isAdmin(HttpSession session) {
        System.out.println("=== ANALYTICS SECURITY CHECK ===");

        if (session == null) {
            System.out.println("SESSION = null");
            return false;
        }

        Object role = session.getAttribute("role");
        System.out.println("SESSION ID   = " + session.getId());
        System.out.println("SESSION ROLE = " + role);

        if (role == null) return false;

        String r = role.toString();
        // Покриваємо "ADMIN", "ROLE_ADMIN", "ROLE_ADMIN,ROLE_USER" і т.п.
        return r.equals("ADMIN")
                || r.equals("ROLE_ADMIN")
                || r.contains("ADMIN");
    }

    @GetMapping("/rules")
    public Map<String, Long> attacksByRule(HttpSession session) {
        if (!isAdmin(session)) return Map.of();

        var events = repo.findAll();
        System.out.println("ANALYTICS /rules, events count = " + events.size());

        return events.stream()
                .collect(Collectors.groupingBy(
                        e -> Optional.ofNullable(e.getRuleTrigger()).orElse("UNKNOWN"),
                        Collectors.counting()
                ));
    }

    @GetMapping("/paths")
    public Map<String, Long> popularPaths(HttpSession session) {
        if (!isAdmin(session)) return Map.of();

        var events = repo.findAll();
        System.out.println("ANALYTICS /paths, events count = " + events.size());

        return events.stream()
                .collect(Collectors.groupingBy(
                        e -> Optional.ofNullable(e.getPath()).orElse("/unknown"),
                        Collectors.counting()
                ));
    }

    @GetMapping("/ip")
    public List<Map.Entry<String, Long>> dangerousIPs(HttpSession session) {
        if (!isAdmin(session)) return List.of();

        var events = repo.findAll();
        System.out.println("ANALYTICS /ip, events count = " + events.size());

        Map<String, Long> ipMap = events.stream()
                .filter(e -> e.getIp() != null && !e.getIp().isBlank())
                .collect(Collectors.groupingBy(
                        e -> e.getIp(),
                        Collectors.counting()
                ));

        return ipMap.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .toList();
    }

    @GetMapping("/hours")
    public Map<Integer, Long> activityByHour(HttpSession session) {
        if (!isAdmin(session)) return Map.of();

        var events = repo.findAll();
        System.out.println("ANALYTICS /hours, events count = " + events.size());

        return events.stream()
                .filter(e -> e.getTimestamp() != null)
                .collect(Collectors.groupingBy(
                        e -> e.getTimestamp().getHour(),
                        Collectors.counting()
                ));
    }

    @GetMapping("/heatmap")
    public Map<Integer, Map<Integer, Long>> heatmap(HttpSession session) {
        if (!isAdmin(session)) return Map.of();

        var events = repo.findAll();
        System.out.println("ANALYTICS /heatmap, events count = " + events.size());

        Map<Integer, Map<Integer, Long>> map = new HashMap<>();

        events.stream()
                .filter(e -> e.getTimestamp() != null)
                .forEach(e -> {
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
        System.out.println("ANALYTICS /risk, events count = " + events.size());

        if (events.isEmpty()) return Map.of();

        int min = events.stream()
                .mapToInt(e -> e.getRiskScore())
                .min()
                .orElse(0);

        int max = events.stream()
                .mapToInt(e -> e.getRiskScore())
                .max()
                .orElse(0);

        double avg = events.stream()
                .mapToInt(e -> e.getRiskScore())
                .average()
                .orElse(0.0);

        return Map.of(
                "min", min,
                "max", max,
                "avg", avg
        );
    }
}
