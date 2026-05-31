package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.dto.FirewallActionRequest;
import com.adaptivesecurity.api.dto.FirewallActionResponse;
import com.adaptivesecurity.api.service.AdaptiveSecurityScheduler;
import com.adaptivesecurity.api.service.FirewallManagementService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/firewall")
@RequiredArgsConstructor
public class FirewallController {

    private final FirewallManagementService firewallManagementService;
    private final AdaptiveSecurityScheduler adaptiveSecurityScheduler;

    @PostMapping("/block")
    public ResponseEntity<FirewallActionResponse> blockIp(@Valid @RequestBody FirewallActionRequest request) {
        FirewallActionResponse response = firewallManagementService.blockIp(request.getIpAddress(), request.getChain());
        if (response.isSuccess()) {
            // Sync in-memory state so the IP shows as BLOCKED in the frontend
            adaptiveSecurityScheduler.addBlockedIp(request.getIpAddress());
        }
        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.internalServerError().body(response);
    }

    @PostMapping("/unblock")
    public ResponseEntity<FirewallActionResponse> unblockIp(@Valid @RequestBody FirewallActionRequest request) {
        FirewallActionResponse response = firewallManagementService.unblockIp(request.getIpAddress(), request.getChain());
        if (response.isSuccess()) {
            // Sync in-memory state so the frontend immediately reflects the unblock
            // and the scheduler can re-detect this IP if it attacks again
            adaptiveSecurityScheduler.removeIp(request.getIpAddress());
        }
        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.internalServerError().body(response);
    }
}
