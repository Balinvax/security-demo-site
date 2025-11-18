package com.securitysite.securitydemosite.security.adaptive;

import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedList;

public class AdaptiveEngine {

    private final MovingWindow<RequestSnapshot> window = new MovingWindow<>(1000);
    private final AdaptiveStats stats = new AdaptiveStats();
    private final AnomalyDetector detector = new AnomalyDetector();

    public synchronized RiskEvent process(HttpServletRequest req, int payloadSize, int statusCode) {

        RequestSnapshot snap = RequestSnapshot.fromRequest(req, payloadSize);

        // додаємо у вікно
        window.add(snap);

        // оновлюємо статистику
        stats.update(snap, statusCode);

        // аналіз
        int risk = detector.detect(snap, stats, window.size());

        return new RiskEvent(risk);
    }
}
