package com.securitysite.securitydemosite.controller;

import com.securitysite.securitydemosite.model.User;
import com.securitysite.securitydemosite.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

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
            // після реєстрації — на сторінку логіну
            return "redirect:/login";
        } catch (IllegalArgumentException ex) {
            // для спрощення просто повертаємо назад
            return "redirect:/register";
        }
    }

    @PostMapping("/login")
    public String login(@RequestParam("email") String email,
                        @RequestParam("password") String password,
                        HttpSession session) {

        User user = userService.authenticate(email, password);
        if (user == null) {
            return "redirect:/login";
        }

        session.setAttribute(SESSION_USER_ID, user.getId());

        // 🔥 Додаємо роль в сесію
        String role = user.getRoles().stream()
                .findFirst()
                .map(r -> r.getName())
                .orElse("USER");

        session.setAttribute("role", role);
        session.setAttribute("isLogged", true);

        return "redirect:/profile";
    }


    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/";
    }
}
