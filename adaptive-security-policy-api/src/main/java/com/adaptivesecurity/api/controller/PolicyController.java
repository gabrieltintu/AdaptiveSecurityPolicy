package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.dto.PolicyUpdateRequest;
import com.adaptivesecurity.api.dto.PolicyView;
import com.adaptivesecurity.api.service.Actor;
import com.adaptivesecurity.api.service.PolicyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/policy")
@RequiredArgsConstructor
public class PolicyController {

    private final PolicyService policyService;

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

    private Actor actorOf(Jwt jwt) {
        return Actor.user(jwt.getSubject(), jwt.getClaimAsString("preferred_username"));
    }
}
