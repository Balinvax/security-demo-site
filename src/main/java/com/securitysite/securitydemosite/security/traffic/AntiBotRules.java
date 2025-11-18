package com.securitysite.securitydemosite.security.bot;

import jakarta.servlet.http.HttpServletRequest;

public class AntiBotRules {

    private static final String[] BAD_UA = {
            "sqlmap", "curl", "wget", "nmap", "nikto",
            "python-requests", "java-http-client", "masscan",
            "dirbuster", "gobuster"
    };

    public boolean isBadUserAgent(HttpServletRequest req) {
        String ua = req.getHeader("User-Agent");
        if (ua == null) return true;

        ua = ua.toLowerCase();
        for (String bad : BAD_UA) {
            if (ua.contains(bad)) return true;
        }
        return false;
    }

    public boolean missingUA(HttpServletRequest req) {
        return req.getHeader("User-Agent") == null;
    }
}
