package com.adaptivesecurity.api.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class SuspiciousIpInfo {
    private String ipAddress;
    private int failedAttempts;
    private String status;        // "WARNING" or "BLOCKED"
    private List<String> sources;
    private LocalDateTime detectedAt;
}
