package com.adaptivesecurity.api.dto;

import com.adaptivesecurity.api.entity.SecurityPolicy;

import java.time.OffsetDateTime;

public record PolicyView(
        int warningThreshold,
        int blockThreshold,
        int detectionWindowMinutes,
        boolean autoBlockEnabled,
        OffsetDateTime updatedAt,
        String updatedBy
) {
    public static PolicyView from(SecurityPolicy policy) {
        return new PolicyView(
                policy.getWarningThreshold(),
                policy.getBlockThreshold(),
                policy.getDetectionWindowMinutes(),
                policy.isAutoBlockEnabled(),
                policy.getUpdatedAt(),
                policy.getUpdatedBy()
        );
    }
}
