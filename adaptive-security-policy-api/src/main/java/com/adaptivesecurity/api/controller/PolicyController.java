package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.dto.FirewallActionResponse;
import com.adaptivesecurity.api.dto.PolicyUpdateRequest;
import com.adaptivesecurity.api.dto.PolicyView;
import com.adaptivesecurity.api.dto.PortKnockingRequest;
import com.adaptivesecurity.api.service.Actor;
import com.adaptivesecurity.api.service.FirewallManagementService;
import com.adaptivesecurity.api.service.PolicyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/policy")
@RequiredArgsConstructor
public class PolicyController {

    private final PolicyService policyService;
    private final FirewallManagementService firewallManagementService;

    @GetMapping
    public PolicyView getPolicy() {
        return policyService.current();
    }

    @PutMapping
    @PreAuthorize("hasRole('ADMIN')")
    public PolicyView updatePolicy(@Valid @RequestBody PolicyUpdateRequest request,
                                   @AuthenticationPrincipal Jwt jwt) {
        return policyService.update(request, actorOf(jwt));
    }

    @PostMapping("/port-knocking")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PolicyView> togglePortKnocking(@RequestBody PortKnockingRequest request,
                                                         @AuthenticationPrincipal Jwt jwt) {
        boolean enabled = Boolean.TRUE.equals(request.enabled());
        FirewallActionResponse fw = firewallManagementService.applyPortKnockingRules(enabled);
        if (!fw.isSuccess()) {
            return ResponseEntity.internalServerError().build();
        }
        return ResponseEntity.ok(policyService.setPortKnocking(enabled, actorOf(jwt)));
    }

    private Actor actorOf(Jwt jwt) {
        return Actor.user(jwt.getSubject(), jwt.getClaimAsString("preferred_username"));
    }
}
