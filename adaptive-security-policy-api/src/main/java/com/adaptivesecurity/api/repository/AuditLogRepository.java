package com.adaptivesecurity.api.repository;

import com.adaptivesecurity.api.entity.AuditLog;
import com.adaptivesecurity.api.entity.enums.AuditAction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<AuditLog> findByAction(AuditAction action, Pageable pageable);

    @Query("SELECT a.action, COUNT(a) FROM AuditLog a GROUP BY a.action")
    List<Object[]> countGroupedByAction();

    @Query("SELECT a.userType, COUNT(a) FROM AuditLog a GROUP BY a.userType")
    List<Object[]> countGroupedByUserType();

    @Query("SELECT a.trackedIp.ipAddress, COUNT(a) FROM AuditLog a WHERE a.trackedIp IS NOT NULL AND a.action IN :actions GROUP BY a.trackedIp.ipAddress ORDER BY COUNT(a) DESC")
    List<Object[]> topIpsByActions(@Param("actions") Collection<AuditAction> actions, Pageable pageable);

    @Query("SELECT a.action, a.createdAt FROM AuditLog a WHERE a.createdAt >= :since")
    List<Object[]> actionTimestampsSince(@Param("since") OffsetDateTime since);
}
