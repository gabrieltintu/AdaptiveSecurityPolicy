package com.adaptivesecurity.api.dto;

import java.util.List;

public record AnalyticsOverview(
        Summary summary,
        List<ActionCount> actionBreakdown,
        List<DailyCount> timeline,
        List<IpCount> topIps
) {
    public record Summary(
            long totalBlocks,
            long totalWarns,
            long totalUnblocks,
            long totalKnocks,
            long totalConfigChanges,
            long totalWhitelistChanges,
            long currentlyBlocked,
            long currentlyWarning,
            long uniqueIps,
            long autoActions,
            long manualActions
    ) {}

    public record ActionCount(String action, long count) {}

    public record DailyCount(String date, long blocks, long warns, long total) {}

    public record IpCount(String ipAddress, long count) {}
}
