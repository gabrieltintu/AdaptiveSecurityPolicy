package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.dto.FirewallActionRequest;
import com.adaptivesecurity.api.dto.FirewallActionResponse;
import com.adaptivesecurity.api.entity.enums.BlockSource;
import com.adaptivesecurity.api.service.Actor;
import com.adaptivesecurity.api.service.AdaptiveSecurityScheduler;
import com.adaptivesecurity.api.service.FirewallManagementService;
import com.adaptivesecurity.api.service.SecurityPersistenceService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/firewall")
@RequiredArgsConstructor
public class FirewallController {

    private final FirewallManagementService firewallManagementService;
    private final AdaptiveSecurityScheduler adaptiveSecurityScheduler;
    private final SecurityPersistenceService persistence;

    @PostMapping("/block")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<FirewallActionResponse> blockIp(@Valid @RequestBody FirewallActionRequest request,
                                                          @AuthenticationPrincipal Jwt jwt) {
        FirewallActionResponse response = firewallManagementService.blockIp(request.getIpAddress(), request.getChain());
        if (response.isSuccess()) {
            // Sync in-memory state so the IP shows as BLOCKED in the frontend
            adaptiveSecurityScheduler.addBlockedIp(request.getIpAddress());
            persistence.recordBlock(request.getIpAddress(), request.getChain(), BlockSource.MANUAL,
                    "Manual block via API", 0, actorOf(jwt));
        }
        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.internalServerError().body(response);
    }

    @PostMapping("/unblock")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<FirewallActionResponse> unblockIp(@Valid @RequestBody FirewallActionRequest request,
                                                            @AuthenticationPrincipal Jwt jwt) {
        FirewallActionResponse response = firewallManagementService.unblockIp(request.getIpAddress(), request.getChain());
        if (response.isSuccess()) {
            // Sync in-memory state so the frontend immediately reflects the unblock
            // and the scheduler can re-detect this IP if it attacks again
            adaptiveSecurityScheduler.removeIp(request.getIpAddress());
            persistence.recordUnblock(request.getIpAddress(),
                    adaptiveSecurityScheduler.baselineFor(request.getIpAddress()), actorOf(jwt));
        }
        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.internalServerError().body(response);
    }

    private Actor actorOf(Jwt jwt) {
        return Actor.user(jwt.getSubject(), jwt.getClaimAsString("preferred_username"));
    }
}
