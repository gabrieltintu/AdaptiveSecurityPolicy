package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.WhitelistEntryView;
import com.adaptivesecurity.api.entity.IpWhitelist;
import com.adaptivesecurity.api.entity.enums.AuditAction;
import com.adaptivesecurity.api.repository.IpWhitelistRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class WhitelistService {

    private final IpWhitelistRepository repository;
    private final AuditService auditService;

    private final Set<String> cache = ConcurrentHashMap.newKeySet();
    private volatile boolean loaded = false;

    @EventListener(ApplicationReadyEvent.class)
    public synchronized void seed() {
        if (loaded) {
            return;
        }
        cache.clear();
        for (IpWhitelist entry : repository.findAll()) {
            cache.add(entry.getIpAddress());
        }
        loaded = true;
        log.info("Seeded IP whitelist from DB: {} entries", cache.size());
    }

    public boolean isWhitelisted(String ip) {
        if (!loaded) {
            seed();
        }
        return cache.contains(ip);
    }

    public List<WhitelistEntryView> list() {
        return repository.findAllByOrderByCreatedAtDesc().stream()
                .map(WhitelistEntryView::from)
                .toList();
    }

    @Transactional
    public WhitelistEntryView add(String ip, String note, Actor actor) {
        if (repository.existsByIpAddress(ip)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "IP " + ip + " is already whitelisted");
        }
        String cleanNote = (note == null || note.isBlank()) ? null : note.trim();
        IpWhitelist entry = IpWhitelist.builder()
                .ipAddress(ip)
                .note(cleanNote)
                .addedBy(actor.username())
                .build();
        IpWhitelist saved = repository.save(entry);
        cache.add(ip);
        auditService.log(AuditAction.WHITELIST_ADD, actor, null,
                "Whitelisted " + ip + (cleanNote != null ? " (" + cleanNote + ")" : ""));
        return WhitelistEntryView.from(saved);
    }

    @Transactional
    public void remove(Long id, Actor actor) {
        IpWhitelist entry = repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Whitelist entry not found"));
        repository.delete(entry);
        cache.remove(entry.getIpAddress());
        auditService.log(AuditAction.WHITELIST_REMOVE, actor, null,
                "Removed " + entry.getIpAddress() + " from whitelist");
    }
}
