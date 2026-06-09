package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.dto.AiCommandRequest;
import com.adaptivesecurity.api.dto.ProposedAction;
import com.adaptivesecurity.api.service.AiPolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/ai")
@RequiredArgsConstructor
public class AiController {

    private final AiPolicyService aiPolicyService;

    @PostMapping("/firewall/interpret")
    @PreAuthorize("hasRole('ADMIN')")
    public List<ProposedAction> interpret(@RequestBody AiCommandRequest request) {
        if (request == null || request.text() == null || request.text().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Empty request");
        }
        try {
            return aiPolicyService.interpret(request.text().trim());
        } catch (IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, e.getMessage());
        }
    }
}
