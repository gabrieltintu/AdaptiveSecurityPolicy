package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.ProposedAction;
import com.adaptivesecurity.api.service.GeminiClient.RawAction;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class AiPolicyService {

    private static final Pattern IP_OR_CIDR = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)(/(\\d|[12]\\d|3[0-2]))?$");
    private static final Set<String> ACTIONS = Set.of("BLOCK", "UNBLOCK", "WHITELIST");
    private static final Set<String> CHAINS = Set.of("ALL", "INPUT", "OUTPUT", "FORWARD");

    private final GeminiClient geminiClient;

    public AiPolicyService(GeminiClient geminiClient) {
        this.geminiClient = geminiClient;
    }

    public List<ProposedAction> interpret(String text) {
        return geminiClient.interpret(text).stream().map(this::validate).toList();
    }

    private ProposedAction validate(RawAction raw) {
        String action = raw.action() == null ? null : raw.action().trim().toUpperCase();
        String ip = raw.ipAddress() == null ? null : raw.ipAddress().trim();
        String chain = raw.chain() == null ? "ALL" : raw.chain().trim().toUpperCase();
        String note = raw.note();

        if (action == null || !ACTIONS.contains(action)) {
            return new ProposedAction(action, ip, chain, note, false, "Unknown action");
        }
        if (ip == null || !IP_OR_CIDR.matcher(ip).matches()) {
            return new ProposedAction(action, ip, chain, note, false, "Invalid IP or CIDR");
        }
        boolean isWhitelist = "WHITELIST".equals(action);
        if (!isWhitelist && !CHAINS.contains(chain)) {
            return new ProposedAction(action, ip, chain, note, false, "Invalid chain");
        }
        return new ProposedAction(action, ip, isWhitelist ? null : chain, note, true, null);
    }
}
