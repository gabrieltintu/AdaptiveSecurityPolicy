package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.SuspiciousIpInfo;
import com.adaptivesecurity.api.utils.AppConstants;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class BruteForceDetectionService {

    private final CommandExecutorService commandExecutor;

    @Value("${security.brute-force.detection-window-minutes:60}")
    private int detectionWindowMinutes;

    private static final Pattern IP_PATTERN = Pattern.compile(AppConstants.FAILED_PASSWORD_IP_REGEX);

    /**
     * Reads failed SSH login attempts from journald within the configured time window.
     * Using a sliding window prevents stale log entries from causing permanent re-blocks.
     */
    public Map<String, Integer> getFailedAttemptsByIp() {
        String cmd    = String.format(AppConstants.AUTH_LOG_CMD, detectionWindowMinutes);
        String output = commandExecutor.execute(cmd);
        Map<String, Integer> attempts = new HashMap<>();

        if (output == null || output.isBlank()
                || output.startsWith("Warning") || output.startsWith("Internal error")) {
            return attempts;
        }

        for (String line : output.split("\n")) {
            Matcher matcher = IP_PATTERN.matcher(line);
            if (matcher.find()) {
                String ip = matcher.group(1);
                attempts.merge(ip, 1, Integer::sum);
            }
        }

        return attempts;
    }

    /**
     * Returns all IPs that exceeded the warning threshold, enriched with their current status.
     */
    public List<SuspiciousIpInfo> getSuspiciousIps(int warningThreshold, Set<String> blockedIps) {
        return getFailedAttemptsByIp().entrySet().stream()
                .filter(e -> e.getValue() >= warningThreshold)
                .map(e -> SuspiciousIpInfo.builder()
                        .ipAddress(e.getKey())
                        .failedAttempts(e.getValue())
                        .status(blockedIps.contains(e.getKey()) ? "BLOCKED" : "WARNING")
                        .detectedAt(LocalDateTime.now())
                        .build())
                .toList();
    }
}
