package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.AnalyticsOverview;
import com.adaptivesecurity.api.entity.enums.ActorType;
import com.adaptivesecurity.api.entity.enums.AuditAction;
import com.adaptivesecurity.api.entity.enums.IpStatus;
import com.adaptivesecurity.api.repository.AuditLogRepository;
import com.adaptivesecurity.api.repository.TrackedIpRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AnalyticsService {

    private static final int MAX_DAYS = 90;
    private static final int TOP_IPS = 8;
    private static final Set<AuditAction> THREAT_ACTIONS = EnumSet.of(AuditAction.BLOCK, AuditAction.WARN);

    private final AuditLogRepository auditLogRepository;
    private final TrackedIpRepository trackedIpRepository;

    @Transactional(readOnly = true)
    public AnalyticsOverview overview(int days) {
        int window = Math.min(Math.max(days, 1), MAX_DAYS);

        Map<AuditAction, Long> byAction = new EnumMap<>(AuditAction.class);
        for (Object[] row : auditLogRepository.countGroupedByAction()) {
            byAction.put((AuditAction) row[0], (Long) row[1]);
        }

        Map<ActorType, Long> byActor = new EnumMap<>(ActorType.class);
        for (Object[] row : auditLogRepository.countGroupedByUserType()) {
            byActor.put((ActorType) row[0], (Long) row[1]);
        }

        AnalyticsOverview.Summary summary = new AnalyticsOverview.Summary(
                count(byAction, AuditAction.BLOCK),
                count(byAction, AuditAction.WARN),
                count(byAction, AuditAction.UNBLOCK),
                count(byAction, AuditAction.KNOCK),
                count(byAction, AuditAction.CONFIG_CHANGE),
                count(byAction, AuditAction.WHITELIST_ADD) + count(byAction, AuditAction.WHITELIST_REMOVE),
                trackedIpRepository.countByCurrentStatus(IpStatus.BLOCKED),
                trackedIpRepository.countByCurrentStatus(IpStatus.WARNING),
                trackedIpRepository.count(),
                byActor.getOrDefault(ActorType.SYSTEM, 0L),
                byActor.getOrDefault(ActorType.USER, 0L)
        );

        List<AnalyticsOverview.ActionCount> breakdown = byAction.entrySet().stream()
                .map(e -> new AnalyticsOverview.ActionCount(e.getKey().name(), e.getValue()))
                .sorted((a, b) -> Long.compare(b.count(), a.count()))
                .toList();

        List<AnalyticsOverview.IpCount> topIps = auditLogRepository
                .topIpsByActions(THREAT_ACTIONS, PageRequest.of(0, TOP_IPS)).stream()
                .map(row -> new AnalyticsOverview.IpCount((String) row[0], (Long) row[1]))
                .toList();

        return new AnalyticsOverview(summary, breakdown, buildTimeline(window), topIps);
    }

    private List<AnalyticsOverview.DailyCount> buildTimeline(int window) {
        ZoneId zone = ZoneId.systemDefault();
        LocalDate start = LocalDate.now(zone).minusDays(window - 1L);
        OffsetDateTime since = start.atStartOfDay(zone).toOffsetDateTime();

        Map<LocalDate, long[]> buckets = new HashMap<>();
        for (Object[] row : auditLogRepository.actionTimestampsSince(since)) {
            AuditAction action = (AuditAction) row[0];
            LocalDate day = ((OffsetDateTime) row[1]).atZoneSameInstant(zone).toLocalDate();
            long[] tally = buckets.computeIfAbsent(day, d -> new long[3]);
            if (action == AuditAction.BLOCK) {
                tally[0]++;
            } else if (action == AuditAction.WARN) {
                tally[1]++;
            }
            tally[2]++;
        }

        List<AnalyticsOverview.DailyCount> timeline = new ArrayList<>(window);
        for (int i = 0; i < window; i++) {
            LocalDate day = start.plusDays(i);
            long[] tally = buckets.getOrDefault(day, new long[3]);
            timeline.add(new AnalyticsOverview.DailyCount(day.toString(), tally[0], tally[1], tally[2]));
        }
        return timeline;
    }

    private long count(Map<AuditAction, Long> source, AuditAction action) {
        return source.getOrDefault(action, 0L);
    }
}
