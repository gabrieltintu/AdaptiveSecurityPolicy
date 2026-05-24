package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.dto.FirewallActionRequest;
import com.adaptivesecurity.api.dto.FirewallActionResponse;
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

    @PostMapping("/block")
    public ResponseEntity<FirewallActionResponse> blockIp(@Valid @RequestBody FirewallActionRequest request) {
        FirewallActionResponse response = firewallManagementService.blockIp(request.getIpAddress(), request.getChain());
        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.internalServerError().body(response);
    }

    @PostMapping("/unblock")
    public ResponseEntity<FirewallActionResponse> unblockIp(@Valid @RequestBody FirewallActionRequest request) {
        FirewallActionResponse response = firewallManagementService.unblockIp(request.getIpAddress(), request.getChain());
        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.internalServerError().body(response);
    }
}
