package com.adaptivesecurity.api.service.detection;

import java.util.Map;

public interface ThreatDetector {
    String category();
    Map<String, Integer> detect(int windowMinutes);
}
