package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.dto.FirewallRule;
import com.adaptivesecurity.api.dto.NetworkConnection;
import com.adaptivesecurity.api.dto.SuspiciousIpInfo;
import com.adaptivesecurity.api.service.AdaptiveSecurityScheduler;
import com.adaptivesecurity.api.service.DetectionService;
import com.adaptivesecurity.api.service.NetworkMonitoringService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/monitoring")
@RequiredArgsConstructor
public class MonitoringController {

    private final NetworkMonitoringService monitoringService;
    private final DetectionService detectionService;
    private final AdaptiveSecurityScheduler adaptiveSecurityScheduler;

    @GetMapping("/connections")
    public List<NetworkConnection> getConnections() {
        return monitoringService.getActiveConnections();
    }

    @GetMapping("/firewall-rules")
    public List<FirewallRule> getFirewallRules() {
        return monitoringService.getFirewallRules();
    }

    @GetMapping("/suspicious-ips")
    public List<SuspiciousIpInfo> getSuspiciousIps() {
        return detectionService.getSuspiciousIps(adaptiveSecurityScheduler.getBlockedIps());
    }
}