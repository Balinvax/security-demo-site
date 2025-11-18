package com.securitysite.securitydemosite.adaptive;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class RequestSnapshot {

    public Instant timestamp;
    public String method;
    public String path;
    public int paramCount;
    public Map<String, String[]> params;
    public String userAgent;
    public int payloadSize;
    public String ip;

    public static RequestSnapshot fromRequest(HttpServletRequest req, int payloadSize) {
        RequestSnapshot snap = new RequestSnapshot();

        snap.timestamp = Instant.now();
        snap.method = req.getMethod();
        snap.path = req.getRequestURI();
        snap.userAgent = req.getHeader("User-Agent");
        snap.payloadSize = payloadSize;
        snap.ip = req.getRemoteAddr();

        snap.params = new HashMap<>();
        Enumeration<String> e = req.getParameterNames();
        while (e.hasMoreElements()) {
            String k = e.nextElement();
            snap.params.put(k, req.getParameterValues(k));
        }

        snap.paramCount = snap.params.size();
        return snap;
    }
}
