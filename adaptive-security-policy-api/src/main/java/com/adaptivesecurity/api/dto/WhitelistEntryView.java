package com.adaptivesecurity.api.dto;

import com.adaptivesecurity.api.entity.IpWhitelist;

import java.time.OffsetDateTime;

public record WhitelistEntryView(
        Long id,
        String ipAddress,
        String note,
        String addedBy,
        OffsetDateTime createdAt
) {
    public static WhitelistEntryView from(IpWhitelist entry) {
        return new WhitelistEntryView(
                entry.getId(),
                entry.getIpAddress(),
                entry.getNote(),
                entry.getAddedBy(),
                entry.getCreatedAt()
        );
    }
}
