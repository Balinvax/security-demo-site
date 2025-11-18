package com.securitysite.securitydemosite.security.adaptive;

import java.util.*;

public class AdaptiveStats {

    public Map<String, Integer> userAgentFreq = new HashMap<>();
    public Map<String, Integer> urlFreq = new HashMap<>();
    public Map<String, Integer> paramFreq = new HashMap<>();
    public int errorCount = 0;

    public synchronized void update(RequestSnapshot snap, int statusCode) {

        userAgentFreq.merge(snap.userAgent == null ? "NULL" : snap.userAgent, 1, Integer::merge);
        urlFreq.merge(snap.path, 1, Integer::merge);

        for (String p : snap.params.keySet()) {
            paramFreq.merge(p, 1, Integer::merge);
        }

        if (statusCode >= 400) errorCount++;
    }
}
