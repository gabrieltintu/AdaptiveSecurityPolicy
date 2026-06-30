package com.adaptivesecurity.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;

@Entity
@Table(name = "security_policy")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityPolicy {

    @Id
    private Long id;

    @Column(name = "warning_threshold", nullable = false)
    private int warningThreshold;

    @Column(name = "block_threshold", nullable = false)
    private int blockThreshold;

    @Column(name = "detection_window_minutes", nullable = false)
    private int detectionWindowMinutes;

    @Column(name = "auto_block_enabled", nullable = false)
    @Builder.Default
    private boolean autoBlockEnabled = true;

    @Column(name = "ssh_bruteforce_enabled", columnDefinition = "boolean not null default true")
    @Builder.Default
    private boolean sshBruteforceEnabled = true;

    @Column(name = "ssh_probe_enabled", columnDefinition = "boolean not null default true")
    @Builder.Default
    private boolean sshProbeEnabled = true;

    @Column(name = "port_scan_enabled", columnDefinition = "boolean not null default true")
    @Builder.Default
    private boolean portScanEnabled = true;

    @Column(name = "conn_flood_enabled", columnDefinition = "boolean not null default false")
    @Builder.Default
    private boolean connFloodEnabled = false;

    @Column(name = "port_knocking_enabled", columnDefinition = "boolean not null default false")
    @Builder.Default
    private boolean portKnockingEnabled = false;

    @Column(name = "port_scan_min_ports", columnDefinition = "integer not null default 5")
    @Builder.Default
    private int portScanMinPorts = 5;

    @Column(name = "conn_flood_min_connections", columnDefinition = "integer not null default 50")
    @Builder.Default
    private int connFloodMinConnections = 50;

    @Column(name = "updated_at", nullable = false)
    @Builder.Default
    private OffsetDateTime updatedAt = OffsetDateTime.now();

    @Column(name = "updated_by", length = 60)
    private String updatedBy;
}
