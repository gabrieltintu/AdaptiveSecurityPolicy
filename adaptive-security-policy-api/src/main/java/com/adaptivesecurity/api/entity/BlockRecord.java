package com.adaptivesecurity.api.entity;

import com.adaptivesecurity.api.entity.enums.BlockSource;
import com.adaptivesecurity.api.entity.enums.BlockStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;

/**
 * One row per block "episode" (an IP can be blocked, unblocked, then blocked
 * again — each is a separate record). Authoritative source for TTL expiry and
 * repeat-offender counting.
 */
@Entity
@Table(name = "block_record", indexes = {
        @Index(name = "idx_block_status", columnList = "status"),
        @Index(name = "idx_block_ip", columnList = "ip_id")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BlockRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "ip_id", nullable = false)
    private TrackedIp trackedIp;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private BlockStatus status;

    @Column(length = 20)
    private String chain;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private BlockSource source;

    @Column(columnDefinition = "text")
    private String reason;

    @Column(name = "blocked_at", nullable = false)
    @Builder.Default
    private OffsetDateTime blockedAt = OffsetDateTime.now();

    @Column(name = "expires_at")
    private OffsetDateTime expiresAt;

    @Column(name = "unblocked_at")
    private OffsetDateTime unblockedAt;
}
