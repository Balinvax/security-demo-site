package com.securitysite.securitydemosite.security.rate;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimiter {

    private static class IpStats {
        int requestsLastMinute = 0;
        long lastReset = Instant.now().getEpochSecond();
        int postRequests30s = 0;
        long postReset = Instant.now().getEpochSecond();
    }

    private final Map<String, IpStats> ipData = new ConcurrentHashMap<>();

    public boolean isRateExceeded(String ip) {
        long now = Instant.now().getEpochSecond();
        IpStats stats = ipData.computeIfAbsent(ip, k -> new IpStats());

        // reset every 60 sec
        if (now - stats.lastReset >= 60) {
            stats.requestsLastMinute = 0;
            stats.lastReset = now;
        }

        stats.requestsLastMinute++;

        return stats.requestsLastMinute > 60; // limit = 60 req/min
    }

    public boolean isPostFlood(String ip) {
        long now = Instant.now().getEpochSecond();
        IpStats stats = ipData.computeIfAbsent(ip, k -> new IpStats());

        if (now - stats.postReset >= 30) {
            stats.postRequests30s = 0;
            stats.postReset = now;
        }

        stats.postRequests30s++;

        return stats.postRequests30s > 10; // 10 POST /30s
    }
}
