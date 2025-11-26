package com.securitysite.securitydemosite.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminController {


    @GetMapping("/admin-events")
    public String adminEvents(HttpSession session) {

        if (session == null) {
            return "redirect:/access-denied";
        }

        Boolean isLogged = (Boolean) session.getAttribute("isLogged");
        Object roleObj = session.getAttribute("role");
        String role = (roleObj != null) ? roleObj.toString() : null;

        boolean isAdmin =
                role != null &&
                        (role.equals("ADMIN")
                                || role.equals("ROLE_ADMIN")
                                || role.contains("ADMIN"));

        if (isLogged == null || !isLogged || !isAdmin) {
            return "redirect:/access-denied";
        }

        return "forward:/admin-events.html";
    }

    @GetMapping("/admin-analytics")
    public String adminAnalytics(HttpSession session) {

        if (session == null) {
            return "redirect:/access-denied";
        }

        Boolean isLogged = (Boolean) session.getAttribute("isLogged");
        Object roleObj = session.getAttribute("role");
        String role = (roleObj != null) ? roleObj.toString() : null;

        boolean isAdmin =
                role != null &&
                        (role.equals("ADMIN")
                                || role.equals("ROLE_ADMIN")
                                || role.contains("ADMIN"));

        if (isLogged == null || !isLogged || !isAdmin) {
            return "redirect:/access-denied";
        }

        return "forward:/admin-analytics.html";
    }


    @GetMapping("/admin")
    public String adminPanel(HttpSession session) {

        if (session == null) {
            return "redirect:/access-denied";
        }

        Boolean isLogged = (Boolean) session.getAttribute("isLogged");
        Object roleObj = session.getAttribute("role");
        String role = (roleObj != null) ? roleObj.toString() : null;

        boolean isAdmin =
                role != null &&
                        (role.equals("ADMIN")
                                || role.equals("ROLE_ADMIN")
                                || role.contains("ADMIN"));

        if (isLogged == null || !isLogged || !isAdmin) {
            return "redirect:/access-denied";
        }

        return "forward:/admin.html";
    }
}
