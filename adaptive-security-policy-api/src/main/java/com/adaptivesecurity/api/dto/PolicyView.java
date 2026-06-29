package com.adaptivesecurity.api.dto;

import com.adaptivesecurity.api.entity.SecurityPolicy;

import java.time.OffsetDateTime;

public record PolicyView(
        int warningThreshold,
        int blockThreshold,
        int detectionWindowMinutes,
        boolean autoBlockEnabled,
        boolean sshBruteforceEnabled,
        boolean sshProbeEnabled,
        boolean portScanEnabled,
        boolean connFloodEnabled,
        int portScanMinPorts,
        int connFloodMinConnections,
        OffsetDateTime updatedAt,
        String updatedBy
) {
    public static PolicyView from(SecurityPolicy policy) {
        return new PolicyView(
                policy.getWarningThreshold(),
                policy.getBlockThreshold(),
                policy.getDetectionWindowMinutes(),
                policy.isAutoBlockEnabled(),
                policy.isSshBruteforceEnabled(),
                policy.isSshProbeEnabled(),
                policy.isPortScanEnabled(),
                policy.isConnFloodEnabled(),
                policy.getPortScanMinPorts(),
                policy.getConnFloodMinConnections(),
                policy.getUpdatedAt(),
                policy.getUpdatedBy()
        );
    }
}
