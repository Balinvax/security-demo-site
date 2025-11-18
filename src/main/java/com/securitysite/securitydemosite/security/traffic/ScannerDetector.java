package com.securitysite.securitydemosite.security.traffic;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ScannerDetector {

    private static class ScannerStats {
        int notFoundCount = 0;
        int forbiddenCount = 0;
        long lastReset = Instant.now().getEpochSecond();
    }

    private final Map<String, ScannerStats> ipData = new ConcurrentHashMap<>();

    public void record404(String ip) {
        ScannerStats stats = ipData.computeIfAbsent(ip, k -> new ScannerStats());
        long now = Instant.now().getEpochSecond();

        if (now - stats.lastReset >= 60) {
            stats.notFoundCount = 0;
            stats.forbiddenCount = 0;
            stats.lastReset = now;
        }

        stats.notFoundCount++;
    }

    public boolean isScanner(String ip) {
        ScannerStats stats = ipData.get(ip);
        if (stats == null) return false;

        return stats.notFoundCount > 15; // 15 404/min — сильна ознака сканера
    }
}
