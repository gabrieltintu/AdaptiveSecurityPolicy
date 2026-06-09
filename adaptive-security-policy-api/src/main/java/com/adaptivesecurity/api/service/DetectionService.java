package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.SuspiciousIpInfo;
import com.adaptivesecurity.api.service.detection.IpThreat;
import com.adaptivesecurity.api.service.detection.ThreatDetector;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class DetectionService {

    private final List<ThreatDetector> detectors;
    private final PolicyService policyService;

    public Map<String, IpThreat> detect() {
        int window = policyService.detectionWindowMinutes();
        Map<String, IpThreat> result = new HashMap<>();
        for (ThreatDetector detector : detectors) {
            if (!policyService.detectorEnabled(detector.category())) {
                continue;
            }
            Map<String, Integer> counts = detector.detect(window);
            for (Map.Entry<String, Integer> entry : counts.entrySet()) {
                result.computeIfAbsent(entry.getKey(), k -> new IpThreat())
                        .addSignal(detector.category(), entry.getValue());
            }
        }
        return result;
    }

    public Map<String, Integer> getThreatCountByIp() {
        Map<String, Integer> counts = new HashMap<>();
        detect().forEach((ip, threat) -> counts.put(ip, threat.totalCount()));
        return counts;
    }

    public List<SuspiciousIpInfo> getSuspiciousIps(Set<String> blockedIps) {
        int warningThreshold = policyService.warningThreshold();
        List<SuspiciousIpInfo> suspicious = new ArrayList<>();
        detect().forEach((ip, threat) -> {
            if (threat.totalCount() >= warningThreshold) {
                suspicious.add(SuspiciousIpInfo.builder()
                        .ipAddress(ip)
                        .failedAttempts(threat.totalCount())
                        .status(blockedIps.contains(ip) ? "BLOCKED" : "WARNING")
                        .sources(threat.categories())
                        .detectedAt(LocalDateTime.now())
                        .build());
            }
        });
        return suspicious;
    }
}
