package com.adaptivesecurity.api.entity;

import com.adaptivesecurity.api.entity.enums.ActorType;
import com.adaptivesecurity.api.entity.enums.AuditAction;
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
 * Append-only audit trail of every action/event in the system. The actor is
 * either a Keycloak user (userType=USER, with snapshot of sub + username) or
 * the system itself (userType=SYSTEM). Powers the History page and charts.
 */
@Entity
@Table(name = "audit_log", indexes = {
        @Index(name = "idx_audit_created", columnList = "created_at"),
        @Index(name = "idx_audit_action", columnList = "action")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private AuditAction action;

    @Enumerated(EnumType.STRING)
    @Column(name = "user_type", nullable = false, length = 10)
    private ActorType userType;

    /** Keycloak "sub" (UUID). Null when userType = SYSTEM. Not a FK — users live in Keycloak. */
    @Column(name = "user_id", length = 64)
    private String userId;

    /** Snapshot of the username at action time ("system" or preferred_username). */
    @Column(nullable = false, length = 60)
    private String username;

    /** The IP this action concerns, if any (null for e.g. CONFIG_CHANGE). */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ip_id")
    private TrackedIp trackedIp;

    @Column(columnDefinition = "text")
    private String details;

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private OffsetDateTime createdAt = OffsetDateTime.now();
}
