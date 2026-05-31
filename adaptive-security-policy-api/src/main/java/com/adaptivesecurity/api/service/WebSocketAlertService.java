package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.AlertEvent;
import com.adaptivesecurity.api.dto.SuspiciousIpInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class WebSocketAlertService {

    private final SimpMessagingTemplate messagingTemplate;

    private static final String ALERTS_TOPIC = "/topic/alerts";

    public void sendWarningAlert(SuspiciousIpInfo info) {
        AlertEvent event = AlertEvent.builder()
                .ipAddress(info.getIpAddress())
                .failedAttempts(info.getFailedAttempts())
                .status("WARNING")
                .message("Suspicious IP detected with " + info.getFailedAttempts() + " failed login attempts.")
                .timestamp(LocalDateTime.now())
                .build();
        messagingTemplate.convertAndSend(ALERTS_TOPIC, event);
    }

    public void sendBlockAlert(SuspiciousIpInfo info) {
        AlertEvent event = AlertEvent.builder()
                .ipAddress(info.getIpAddress())
                .failedAttempts(info.getFailedAttempts())
                .status("BLOCKED")
                .message("IP automatically blocked after " + info.getFailedAttempts() + " failed login attempts.")
                .timestamp(LocalDateTime.now())
                .build();
        messagingTemplate.convertAndSend(ALERTS_TOPIC, event);
    }

    public void sendPortKnockAlert(String ipAddress, int port) {
        AlertEvent event = AlertEvent.builder()
                .ipAddress(ipAddress)
                .failedAttempts(0)
                .status("KNOCK")
                .message("Port " + port + " temporarily opened via port knocking for " + ipAddress + ".")
                .timestamp(LocalDateTime.now())
                .build();
        messagingTemplate.convertAndSend(ALERTS_TOPIC, event);
    }
}
