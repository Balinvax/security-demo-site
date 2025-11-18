package com.securitysite.securitydemosite.controller;

import com.securitysite.securitydemosite.model.User;
import com.securitysite.securitydemosite.repository.UserRepository;
import com.securitysite.securitydemosite.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
public class ApiController {

    private final UserService userService;
    private final UserRepository userRepository;

    public ApiController(UserService userService, UserRepository userRepository) {
        this.userService = userService;
        this.userRepository = userRepository;
    }

    // ---------------------------------------------------------
    // /api/auth/me  (без змін)
    // ---------------------------------------------------------
    @GetMapping("/api/auth/me")
    public ResponseEntity<?> currentUser(HttpSession session) {
        Object idObj = session.getAttribute(AuthController.SESSION_USER_ID);

        Map<String, Object> data = new HashMap<>();

        if (idObj == null) {
            data.put("authenticated", false);
            return ResponseEntity.ok(data);
        }

        UUID userId = (UUID) idObj;

        User user = userService.findById(userId).orElse(null);
        if (user == null) {
            data.put("authenticated", false);
            return ResponseEntity.ok(data);
        }

        data.put("authenticated", true);
        data.put("fullName", user.getFullName());
        data.put("email", user.getEmail());

        return ResponseEntity.ok(data);
    }

    // ---------------------------------------------------------
    // /api/public  (без змін)
    // ---------------------------------------------------------
    @GetMapping("/api/public")
    public Map<String, String> publicData() {
        Map<String, String> data = new HashMap<>();
        data.put("message", "This is public data");
        return data;
    }

    // ---------------------------------------------------------
    // /api/users  (ВИПРАВЛЕНО)
    // ---------------------------------------------------------
    @GetMapping("/api/users")
    public List<Map<String, Object>> getUsers(HttpSession session) {

        Boolean isLogged = (Boolean) session.getAttribute("isLogged");
        String role = (String) session.getAttribute("role");

        if (isLogged == null || !isLogged || role == null || !role.equals("ADMIN")) {
            return Collections.emptyList();
        }

        List<User> users = userRepository.findAll();

        List<Map<String, Object>> result = new ArrayList<>();

        for (User u : users) {
            Map<String, Object> obj = new HashMap<>();
            obj.put("id", u.getId().toString());
            obj.put("email", u.getEmail());
            obj.put("fullName", u.getFullName());
            result.add(obj);
        }

        return result;
    }
}
