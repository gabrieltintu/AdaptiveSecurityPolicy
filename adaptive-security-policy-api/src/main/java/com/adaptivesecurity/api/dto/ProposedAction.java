package com.adaptivesecurity.api.dto;

public record ProposedAction(
        String action,
        String ipAddress,
        String chain,
        String note,
        boolean valid,
        String error) {
}
