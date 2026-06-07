package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.AuditEventView;
import com.adaptivesecurity.api.entity.AuditLog;
import com.adaptivesecurity.api.entity.TrackedIp;
import com.adaptivesecurity.api.entity.enums.AuditAction;
import com.adaptivesecurity.api.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public void log(AuditAction action, Actor actor, TrackedIp trackedIp, String details) {
        AuditLog entry = AuditLog.builder()
                .action(action)
                .userType(actor.type())
                .userId(actor.userId())
                .username(actor.username())
                .trackedIp(trackedIp)
                .details(details)
                .build();
        auditLogRepository.save(entry);
    }

    @Transactional(readOnly = true)
    public Page<AuditEventView> recentEvents(Pageable pageable) {
        return auditLogRepository.findAllByOrderByCreatedAtDesc(pageable).map(AuditEventView::from);
    }
}
