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

    @Column(name = "updated_at", nullable = false)
    @Builder.Default
    private OffsetDateTime updatedAt = OffsetDateTime.now();

    @Column(name = "updated_by", length = 60)
    private String updatedBy;
}
