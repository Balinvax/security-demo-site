package com.securitysite.securitydemosite.controller;

import com.securitysite.securitydemosite.model.User;
import com.securitysite.securitydemosite.model.Role;
import com.securitysite.securitydemosite.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

@Controller
@RequestMapping("/auth")
public class AuthController {

    public static final String SESSION_USER_ID = "USER_ID";

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public String register(@RequestParam("fullName") String fullName,
                           @RequestParam("email") String email,
                           @RequestParam("password") String password) {
        try {
            userService.registerUser(fullName, email, password);
            return "redirect:/login";
        } catch (IllegalArgumentException ex) {
            return "redirect:/register";
        }
    }

    @PostMapping("/login")
    public String login(@RequestParam("email") String email,
                        @RequestParam("password") String password,
                        HttpSession session) {

        User user = userService.authenticate(email, password);
        if (user == null) {
            // невдалий логін
            return "redirect:/login";
        }

        // базові атрибути сесії
        session.setAttribute(SESSION_USER_ID, user.getId());
        session.setAttribute("isLogged", true);

        // ===== ВИЗНАЧЕННЯ РОЛІ =====
        String sessionRole = "ROLE_USER";   // за замовчуванням

        boolean isAdminByRole = false;
        boolean isAdminByEmail = "admin@admin.com".equalsIgnoreCase(user.getEmail());

        try {
            if (user.getRoles() != null && !user.getRoles().isEmpty()) {
                System.out.println("USER ROLES FOR " + user.getEmail() + ":");
                for (Role role : user.getRoles()) {
                    if (role == null) continue;
                    System.out.println("  - ROLE ID=" + role.getId() + ", NAME=" + role.getName());
                }

                isAdminByRole = user.getRoles().stream()
                        .filter(Objects::nonNull)
                        .map(Role::getName)
                        .filter(Objects::nonNull)
                        .map(String::toUpperCase)
                        .anyMatch(name -> name.contains("ADMIN"));
            }
        } catch (Exception ex) {
            System.out.println("ERROR RESOLVING USER ROLES FOR USER ID = "
                    + user.getId() + ": " + ex.getClass().getName() + " - " + ex.getMessage());
        }

        if (isAdminByRole || isAdminByEmail) {
            sessionRole = "ROLE_ADMIN";
        }

        session.setAttribute("role", sessionRole);

        System.out.println("=== LOGIN SUCCESS ===");
        System.out.println("USER ID      = " + user.getId());
        System.out.println("EMAIL        = " + user.getEmail());
        System.out.println("SESSION ID   = " + session.getId());
        System.out.println("SESSION ROLE = " + sessionRole);
        System.out.println("isAdminByRole  = " + isAdminByRole);
        System.out.println("isAdminByEmail = " + isAdminByEmail);

        return "redirect:/profile";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        if (session != null) {
            System.out.println("=== LOGOUT === SESSION ID = " + session.getId());
            session.invalidate();
        }
        return "redirect:/";
    }
}
