package com.securitysite.securitydemosite.security.adaptive;

public class AnomalyDetector {

    public int detect(RequestSnapshot snap, AdaptiveStats stats, int windowSize) {
        int risk = 0;

        // Новий User-Agent
        if (!stats.userAgentFreq.containsKey(snap.userAgent)) {
            risk += 2;
        }

        // Непопулярний URL
        int urlCount = stats.urlFreq.getOrDefault(snap.path, 0);
        if (urlCount < (windowSize * 0.0005)) {
            risk += 2;
        }

        // Нові параметри
        for (String p : snap.params.keySet()) {
            if (!stats.paramFreq.containsKey(p)) {
                risk += 5;
            }
        }

        // Payload anomaly
        if (snap.payloadSize > 20000) risk += 3;

        // Частота помилок
        double errorRate = (double) stats.errorCount / Math.max(windowSize, 1);
        if (errorRate > 0.15) {
            risk += 10;
        }

        return risk;
    }
}
