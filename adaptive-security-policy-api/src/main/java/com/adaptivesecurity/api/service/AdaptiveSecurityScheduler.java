package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.FirewallActionResponse;
import com.adaptivesecurity.api.dto.SuspiciousIpInfo;
import com.adaptivesecurity.api.service.detection.IpThreat;
import com.adaptivesecurity.api.entity.TrackedIp;
import com.adaptivesecurity.api.entity.enums.BlockSource;
import com.adaptivesecurity.api.entity.enums.IpStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdaptiveSecurityScheduler {

    private final DetectionService detectionService;
    private final FirewallManagementService firewallManagementService;
    private final AlertService alertService;
    private final WebSocketAlertService webSocketAlertService;
    private final SecurityPersistenceService persistence;
    private final PolicyService policyService;
    private final WhitelistService whitelistService;
    private final Set<String>             warnedIps      = ConcurrentHashMap.newKeySet();
    private final Set<String>             blockedIps     = ConcurrentHashMap.newKeySet();
    private final ConcurrentMap<String, Integer> attemptBaseline = new ConcurrentHashMap<>();

    private volatile boolean ready = false;

    @EventListener(ApplicationReadyEvent.class)
    public void seedFromDb() {
        for (TrackedIp trackedIp : persistence.findAllTrackedIps()) {
            String ip = trackedIp.getIpAddress();
            if (trackedIp.getCurrentStatus() == IpStatus.BLOCKED) {
                blockedIps.add(ip);
                warnedIps.add(ip);
            } else if (trackedIp.getCurrentStatus() == IpStatus.WARNING) {
                warnedIps.add(ip);
            }
            if (trackedIp.getAttemptBaseline() > 0) {
                attemptBaseline.put(ip, trackedIp.getAttemptBaseline());
            }
        }
        ready = true;
        log.info("Seeded security state from DB: {} blocked, {} warned IPs", blockedIps.size(), warnedIps.size());
    }

    @Scheduled(fixedRateString = "${security.brute-force.scheduler-interval-ms}")
    public void scan() {
        if (!ready) {
            return;
        }
        Map<String, IpThreat> threats = detectionService.detect();

        int     warningThreshold = policyService.warningThreshold();
        int     blockThreshold   = policyService.blockThreshold();
        boolean autoBlock        = policyService.autoBlockEnabled();

        for (Map.Entry<String, IpThreat> entry : threats.entrySet()) {
            String ip = entry.getKey();
            // Whitelisted IPs are never auto-warned or auto-blocked
            if (whitelistService.isWhitelisted(ip)) {
                continue;
            }
            IpThreat threat = entry.getValue();
            int    raw   = threat.totalCount();
            // Subtract signals that existed before the last unblock so the IP isn't immediately re-blocked
            int    count = Math.max(0, raw - attemptBaseline.getOrDefault(ip, 0));
            String sources = String.join(", ", threat.categories());

            SuspiciousIpInfo info = SuspiciousIpInfo.builder()
                    .ipAddress(ip)
                    .failedAttempts(count)
                    .sources(threat.categories())
                    .detectedAt(LocalDateTime.now())
                    .build();

            if (autoBlock && count >= blockThreshold && !blockedIps.contains(ip)) {
                FirewallActionResponse blockResult = firewallManagementService.blockIp(ip, "ALL");
                if (!blockResult.isSuccess()) {
                    log.warn("Auto-block command failed for IP {} — {}", ip, blockResult.getMessage());
                    continue;
                }
                webSocketAlertService.sendBlockAlert(info);
                blockedIps.add(ip);
                warnedIps.add(ip);
                trySendEmail(() -> alertService.sendBlockAlert(info), ip, "block");
                tryPersist(() -> persistence.recordBlock(ip, "ALL", BlockSource.AUTO,
                        "Auto-block after " + count + " suspicious signals (" + sources + ")", count, Actor.system()), ip, "block");

            } else if (count >= warningThreshold && !warnedIps.contains(ip)) {
                webSocketAlertService.sendWarningAlert(info);
                warnedIps.add(ip);
                trySendEmail(() -> alertService.sendWarningAlert(info), ip, "warning");
                tryPersist(() -> persistence.recordWarning(ip, count, sources, Actor.system()), ip, "warning");
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

    private void tryPersist(Runnable persistAction, String ip, String type) {
        try {
            persistAction.run();
        } catch (Exception e) {
            log.warn("DB persistence ({}) failed for IP {} — {}", type, ip, e.getMessage());
        }
    }

    public int baselineFor(String ip) {
        return attemptBaseline.getOrDefault(ip, 0);
    }

    public Set<String> getBlockedIps() {
        return Collections.unmodifiableSet(blockedIps);
    }

    /**
     * Marks an IP as blocked in the in-memory state (used after a manual block via the API)
     * so it shows as BLOCKED in the frontend and the scheduler treats it as already handled.
     */
    public void addBlockedIp(String ip) {
        blockedIps.add(ip);
        warnedIps.add(ip);
    }

    /**
     * Removes an IP from both in-memory sets so the frontend no longer shows it
     * as BLOCKED/WARNING, and the scheduler can re-detect it if it attacks again.
     * Snapshots the current attempt count as a baseline so old log entries don't
     * cause an immediate re-block after unblocking.
     */
    public void removeIp(String ip) {
        blockedIps.remove(ip);
        warnedIps.remove(ip);
        int currentCount = detectionService.getThreatCountByIp().getOrDefault(ip, 0);
        attemptBaseline.put(ip, currentCount);
    }
}
