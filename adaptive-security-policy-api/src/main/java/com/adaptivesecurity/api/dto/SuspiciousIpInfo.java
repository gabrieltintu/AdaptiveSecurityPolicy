package com.adaptivesecurity.api.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class SuspiciousIpInfo {
    private String ipAddress;
    private int failedAttempts;
    private String status;        // "WARNING" or "BLOCKED"
    private LocalDateTime detectedAt;
}
