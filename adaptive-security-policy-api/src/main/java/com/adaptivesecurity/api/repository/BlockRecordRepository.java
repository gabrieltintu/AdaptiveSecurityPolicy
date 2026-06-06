package com.adaptivesecurity.api.repository;

import com.adaptivesecurity.api.entity.BlockRecord;
import com.adaptivesecurity.api.entity.TrackedIp;
import com.adaptivesecurity.api.entity.enums.BlockStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

public interface BlockRecordRepository extends JpaRepository<BlockRecord, Long> {

    List<BlockRecord> findByStatus(BlockStatus status);

    /** Blocks that should be auto-unblocked (TTL expired). */
    List<BlockRecord> findByStatusAndExpiresAtBefore(BlockStatus status, OffsetDateTime time);

    /** How many times this IP has been blocked — drives repeat-offender escalation. */
    long countByTrackedIp(TrackedIp trackedIp);

    Optional<BlockRecord> findFirstByTrackedIpAndStatusOrderByBlockedAtDesc(TrackedIp trackedIp, BlockStatus status);
}
