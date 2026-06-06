package com.adaptivesecurity.api.entity;

import com.adaptivesecurity.api.entity.enums.IpStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;

/**
 * Master record for every IP the system has observed. Holds the current state
 * (fast reads) plus, later, enrichment data (geo, threat score). Other tables
 * reference this one by FK.
 */
@Entity
@Table(name = "tracked_ip")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TrackedIp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, unique = true, length = 45)
    private String ipAddress;

    @Enumerated(EnumType.STRING)
    @Column(name = "current_status", nullable = false, length = 20)
    @Builder.Default
    private IpStatus currentStatus = IpStatus.WARNING;

    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private int failedAttempts = 0;

    /** Baseline subtracted from journal counts after an unblock (prevents stale re-blocks). */
    @Column(name = "attempt_baseline", nullable = false)
    @Builder.Default
    private int attemptBaseline = 0;

    @Column(length = 60)
    private String country;

    @Column(length = 80)
    private String city;

    @Column(name = "threat_score")
    private Integer threatScore;

    @Column(nullable = false)
    @Builder.Default
    private boolean whitelisted = false;

    @Column(name = "first_seen", nullable = false, updatable = false)
    @Builder.Default
    private OffsetDateTime firstSeen = OffsetDateTime.now();

    @Column(name = "last_seen", nullable = false)
    @Builder.Default
    private OffsetDateTime lastSeen = OffsetDateTime.now();
}
