package com.adaptivesecurity.api.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class AlertEvent {
    private String ipAddress;
    private int failedAttempts;
    private String status;      // "WARNING" or "BLOCKED"
    private String message;
    private LocalDateTime timestamp;
}
