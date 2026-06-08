package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.dto.WhitelistAddRequest;
import com.adaptivesecurity.api.dto.WhitelistEntryView;
import com.adaptivesecurity.api.service.Actor;
import com.adaptivesecurity.api.service.WhitelistService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/whitelist")
@RequiredArgsConstructor
public class WhitelistController {

    private final WhitelistService whitelistService;

    @GetMapping
    public List<WhitelistEntryView> list() {
        return whitelistService.list();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ADMIN')")
    public WhitelistEntryView add(@Valid @RequestBody WhitelistAddRequest request,
                                  @AuthenticationPrincipal Jwt jwt) {
        return whitelistService.add(request.getIpAddress(), request.getNote(), actorOf(jwt));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('ADMIN')")
    public void remove(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        whitelistService.remove(id, actorOf(jwt));
    }

    private Actor actorOf(Jwt jwt) {
        return Actor.user(jwt.getSubject(), jwt.getClaimAsString("preferred_username"));
    }
}
