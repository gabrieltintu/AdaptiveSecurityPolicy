package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.SuspiciousIpInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdaptiveSecurityScheduler {

    private final BruteForceDetectionService bruteForceDetectionService;
    private final FirewallManagementService firewallManagementService;
    private final AlertService alertService;
    private final WebSocketAlertService webSocketAlertService;

    @Value("${security.brute-force.warning-threshold}")
    private int warningThreshold;

    @Value("${security.brute-force.block-threshold}")
    private int blockThreshold;

    // In-memory state — resets on app restart (replaced by DB in future)
    private final Set<String> warnedIps  = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();

    @Scheduled(fixedRateString = "${security.brute-force.scheduler-interval-ms}")
    public void scan() {
        Map<String, Integer> failedAttempts = bruteForceDetectionService.getFailedAttemptsByIp();

        for (Map.Entry<String, Integer> entry : failedAttempts.entrySet()) {
            String ip    = entry.getKey();
            int    count = entry.getValue();

            SuspiciousIpInfo info = SuspiciousIpInfo.builder()
                    .ipAddress(ip)
                    .failedAttempts(count)
                    .detectedAt(LocalDateTime.now())
                    .build();

            if (count >= blockThreshold && !blockedIps.contains(ip)) {
                firewallManagementService.blockIp(ip, "ALL");
                webSocketAlertService.sendBlockAlert(info);
                blockedIps.add(ip);
                warnedIps.add(ip);
                trySendEmail(() -> alertService.sendBlockAlert(info), ip, "block");

            } else if (count >= warningThreshold && !warnedIps.contains(ip)) {
                webSocketAlertService.sendWarningAlert(info);
                warnedIps.add(ip);
                trySendEmail(() -> alertService.sendWarningAlert(info), ip, "warning");
            }
        }
    }

    private void trySendEmail(Runnable emailAction, String ip, String type) {
        try {
            emailAction.run();
        } catch (Exception e) {
            log.warn("Email alert ({}) failed for IP {} — {}", type, ip, e.getMessage());
        }
    }

    public Set<String> getBlockedIps() {
        return Collections.unmodifiableSet(blockedIps);
    }
}
