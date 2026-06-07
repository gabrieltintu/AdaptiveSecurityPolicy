package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.entity.BlockRecord;
import com.adaptivesecurity.api.entity.TrackedIp;
import com.adaptivesecurity.api.entity.enums.AuditAction;
import com.adaptivesecurity.api.entity.enums.BlockSource;
import com.adaptivesecurity.api.entity.enums.BlockStatus;
import com.adaptivesecurity.api.entity.enums.IpStatus;
import com.adaptivesecurity.api.repository.BlockRecordRepository;
import com.adaptivesecurity.api.repository.TrackedIpRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SecurityPersistenceService {

    private final TrackedIpRepository trackedIpRepository;
    private final BlockRecordRepository blockRecordRepository;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public boolean isWhitelisted(String ipAddress) {
        return trackedIpRepository.existsByIpAddressAndWhitelistedTrue(ipAddress);
    }

    @Transactional(readOnly = true)
    public List<TrackedIp> findAllTrackedIps() {
        return trackedIpRepository.findAll();
    }

    @Transactional
    public void recordWarning(String ipAddress, int attempts, Actor actor) {
        TrackedIp trackedIp = upsert(ipAddress);
        trackedIp.setFailedAttempts(attempts);
        trackedIp.setLastSeen(OffsetDateTime.now());
        if (trackedIp.getCurrentStatus() != IpStatus.BLOCKED) {
            trackedIp.setCurrentStatus(IpStatus.WARNING);
        }
        trackedIpRepository.save(trackedIp);
        auditService.log(AuditAction.WARN, actor, trackedIp,
                "Warning: " + attempts + " failed SSH login attempts");
    }

    @Transactional
    public void recordBlock(String ipAddress, String chain, BlockSource source, String reason, int attempts, Actor actor) {
        TrackedIp trackedIp = upsert(ipAddress);
        trackedIp.setFailedAttempts(Math.max(trackedIp.getFailedAttempts(), attempts));
        trackedIp.setCurrentStatus(IpStatus.BLOCKED);
        trackedIp.setLastSeen(OffsetDateTime.now());
        trackedIpRepository.save(trackedIp);

        BlockRecord blockRecord = BlockRecord.builder()
                .trackedIp(trackedIp)
                .status(BlockStatus.ACTIVE)
                .chain(chain)
                .source(source)
                .reason(reason)
                .blockedAt(OffsetDateTime.now())
                .build();
        blockRecordRepository.save(blockRecord);

        auditService.log(AuditAction.BLOCK, actor, trackedIp, reason);
    }

    @Transactional
    public void recordUnblock(String ipAddress, int attemptBaseline, Actor actor) {
        TrackedIp trackedIp = trackedIpRepository.findByIpAddress(ipAddress).orElse(null);
        if (trackedIp == null) {
            auditService.log(AuditAction.UNBLOCK, actor, null, "Unblocked untracked IP " + ipAddress);
            return;
        }
        for (BlockRecord active : blockRecordRepository.findByTrackedIpAndStatus(trackedIp, BlockStatus.ACTIVE)) {
            active.setStatus(BlockStatus.REMOVED);
            active.setUnblockedAt(OffsetDateTime.now());
            blockRecordRepository.save(active);
        }
        trackedIp.setCurrentStatus(IpStatus.CLEARED);
        trackedIp.setAttemptBaseline(attemptBaseline);
        trackedIp.setLastSeen(OffsetDateTime.now());
        trackedIpRepository.save(trackedIp);
        auditService.log(AuditAction.UNBLOCK, actor, trackedIp,
                "Unblocked (baseline reset to " + attemptBaseline + ")");
    }

    private TrackedIp upsert(String ipAddress) {
        return trackedIpRepository.findByIpAddress(ipAddress)
                .orElseGet(() -> TrackedIp.builder().ipAddress(ipAddress).build());
    }
}
