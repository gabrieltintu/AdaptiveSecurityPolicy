package com.adaptivesecurity.api.dto;

import com.adaptivesecurity.api.entity.AuditLog;

import java.time.OffsetDateTime;

public record AuditEventView(
        Long id,
        String action,
        String userType,
        String username,
        String ipAddress,
        String details,
        OffsetDateTime createdAt
) {
    public static AuditEventView from(AuditLog log) {
        return new AuditEventView(
                log.getId(),
                log.getAction().name(),
                log.getUserType().name(),
                log.getUsername(),
                log.getTrackedIp() != null ? log.getTrackedIp().getIpAddress() : null,
                log.getDetails(),
                log.getCreatedAt()
        );
    }
}
