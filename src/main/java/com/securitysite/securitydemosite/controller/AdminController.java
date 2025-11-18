package com.securitysite.securitydemosite.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminController {

    @GetMapping("/admin")
    public String adminPanel(HttpSession session) {

        Boolean isLogged = (Boolean) session.getAttribute("isLogged");
        String role = (String) session.getAttribute("role");

        if (isLogged == null || !isLogged || role == null || !role.equals("ADMIN")) {
            return "redirect:/access-denied";
        }

        return "forward:/admin.html";
    }
}
