package com.securitysite.securitydemosite.controller;

import com.securitysite.securitydemosite.model.SecurityEvent;
import com.securitysite.securitydemosite.repository.SecurityEventRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/events")
public class SecurityEventsApi {

    private final SecurityEventRepository repo;

    public SecurityEventsApi(SecurityEventRepository repo) {
        this.repo = repo;
    }

    // ====== Перевірка ролі ======
    private boolean isAdmin(HttpSession session) {
        if (session == null) {
            return false;
        }

        Object role = session.getAttribute("role");
        if (role == null) return false;

        String r = role.toString();
        // "ADMIN", "ROLE_ADMIN", "ROLE_ADMIN,ROLE_USER" і т.п.
        return r.equals("ADMIN")
                || r.equals("ROLE_ADMIN")
                || r.contains("ADMIN");
    }

    // ====== Базовий ендпоїнт ======

    @GetMapping
    public List<SecurityEvent> getAll(HttpSession session) {
        if (!isAdmin(session)) return List.of();
        return repo.findAll();
    }

    // ====== Старі ендпоїнти (можна лишити) ======

    @GetMapping("/ip/{ip}")
    public List<SecurityEvent> getByIp(@PathVariable("ip") String ip,
                                       HttpSession session) {
        if (!isAdmin(session)) return List.of();

        if ("127.0.0.1".equals(ip)
                || "localhost".equalsIgnoreCase(ip)
                || "::1".equals(ip)) {
            ip = "0:0:0:0:0:0:0:1";
        }

        return repo.findByIp(ip);
    }

    @GetMapping("/rule/{rule}")
    public List<SecurityEvent> getByRule(@PathVariable("rule") String rule,
                                         HttpSession session) {
        if (!isAdmin(session)) return List.of();
        return repo.findByRuleTrigger(rule);
    }

    @GetMapping("/date")
    public List<SecurityEvent> getByDate(@RequestParam("start") String start,
                                         @RequestParam("end") String end,
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

    // ====== КОМБІНОВАНИЙ ФІЛЬТР /filter ======

    @GetMapping("/filter")
    public List<SecurityEvent> filter(
            @RequestParam(name = "ip", required = false) String ip,
            @RequestParam(name = "rule", required = false) String rule,
            @RequestParam(name = "start", required = false) String start,
            @RequestParam(name = "end", required = false) String end,
            HttpSession session) {

        if (!isAdmin(session)) return List.of();

        // Нормалізуємо пусті строки -> null
        String normalizedIp = (ip != null && !ip.isBlank()) ? ip : null;
        String normalizedRule = (rule != null && !rule.isBlank()) ? rule : null;

        // Нормалізація localhost
        if (normalizedIp != null &&
                ("127.0.0.1".equals(normalizedIp)
                        || "localhost".equalsIgnoreCase(normalizedIp)
                        || "::1".equals(normalizedIp))) {
            normalizedIp = "0:0:0:0:0:0:0:1";
        }

        LocalDateTime startDt = parseClientDateTime(start);
        LocalDateTime endDt   = parseClientDateTime(end);

        // Робимо final-копії для використання в лямбдах
        final String ipFilter   = normalizedIp;
        final String ruleFilter = normalizedRule;
        final LocalDateTime sFilter = startDt;
        final LocalDateTime eFilter = endDt;

        // Базовий список всіх подій
        List<SecurityEvent> events = repo.findAll();

        // Фільтрація в пам'яті
        return events.stream()
                // IP
                .filter(ev -> ipFilter == null ||
                        (ev.getIp() != null && ev.getIp().equals(ipFilter)))
                // правило (по частині, без регістру)
                .filter(ev -> {
                    if (ruleFilter == null) return true;
                    String rt = ev.getRuleTrigger();
                    return rt != null && rt.toLowerCase().contains(ruleFilter.toLowerCase());
                })
                // дата від
                .filter(ev -> {
                    if (sFilter == null) return true;
                    LocalDateTime t = ev.getTimestamp();
                    return t != null && !t.isBefore(sFilter);
                })
                // дата до
                .filter(ev -> {
                    if (eFilter == null) return true;
                    LocalDateTime t = ev.getTimestamp();
                    return t != null && !t.isAfter(eFilter);
                })
                // сортировка за часом (нові зверху)
                .sorted(Comparator.comparing(SecurityEvent::getTimestamp).reversed())
                .collect(Collectors.toList());
    }

    // ====== Парсинг дати з клієнта ======

    private LocalDateTime parseClientDateTime(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        try {
            // пробуємо стандартний ISO-формат
            return LocalDateTime.parse(value);
        } catch (DateTimeParseException ex) {
            try {
                // формат від <input type="datetime-local">
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
