package com.securitysite.securitydemosite.service;

import com.securitysite.securitydemosite.model.SecurityEvent;
import com.securitysite.securitydemosite.repository.SecurityEventRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class SecurityLogService {

    private final SecurityEventRepository repo;

    public SecurityLogService(SecurityEventRepository repo) {
        this.repo = repo;
    }

    public void log(HttpServletRequest req,
                    String rule,
                    int riskScore,
                    String decision,
                    Map<String, String[]> params) {

        SecurityEvent ev = new SecurityEvent();
        ev.setIp(req.getRemoteAddr());
        ev.setMethod(req.getMethod());
        ev.setPath(req.getRequestURI());
        ev.setRuleTrigger(rule);
        ev.setRiskScore(riskScore);
        ev.setDecision(decision);

        if (params != null) {
            ev.setParams(params.toString());
        } else {
            ev.setParams("");
        }

        repo.save(ev);
    }
}
