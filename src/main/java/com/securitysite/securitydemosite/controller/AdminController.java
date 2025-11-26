package com.securitysite.securitydemosite.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminController {

    @GetMapping("/admin")
    public String adminPanel(HttpSession session) {

        if (session == null) {
            return "redirect:/access-denied";
        }

        Boolean isLogged = (Boolean) session.getAttribute("isLogged");
        Object roleObj = session.getAttribute("role");
        String role = (roleObj != null) ? roleObj.toString() : null;

        System.out.println("=== ADMIN PAGE CHECK ===");
        System.out.println("SESSION ID   = " + session.getId());
        System.out.println("isLogged     = " + isLogged);
        System.out.println("SESSION ROLE = " + role);

        boolean isAdmin =
                role != null &&
                        (role.equals("ADMIN")
                                || role.equals("ROLE_ADMIN")
                                || role.contains("ADMIN"));

        if (isLogged == null || !isLogged || !isAdmin) {
            return "redirect:/access-denied";
        }

        // admin.html має лежати в src/main/resources/static
        // Тоді forward:/admin.html віддасть саме цей файл
        return "forward:/admin.html";
    }
}
