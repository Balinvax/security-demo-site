package com.securitysite.securitydemosite.security.adaptive;

import java.util.HashMap;
import java.util.Map;

public class AdaptiveStats {

    public Map<String, Integer> userAgentFreq = new HashMap<>();
    public Map<String, Integer> urlFreq = new HashMap<>();
    public Map<String, Integer> paramFreq = new HashMap<>();
    public int errorCount = 0;

    public synchronized void update(RequestSnapshot snap, int statusCode) {

        userAgentFreq.merge(
                snap.userAgent == null ? "NULL" : snap.userAgent,
                1,
                Integer::sum
        );

        urlFreq.merge(snap.path, 1, Integer::sum);

        for (String p : snap.params.keySet()) {
            paramFreq.merge(p, 1, Integer::sum);
        }

        if (statusCode >= 400) {
            errorCount++;
        }
    }
}
