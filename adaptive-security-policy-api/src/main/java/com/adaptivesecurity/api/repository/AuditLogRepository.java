package com.adaptivesecurity.api.repository;

import com.adaptivesecurity.api.entity.AuditLog;
import com.adaptivesecurity.api.entity.enums.AuditAction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<AuditLog> findByAction(AuditAction action, Pageable pageable);
}
