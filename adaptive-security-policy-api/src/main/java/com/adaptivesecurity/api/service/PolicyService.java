package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.PolicyUpdateRequest;
import com.adaptivesecurity.api.dto.PolicyView;
import com.adaptivesecurity.api.entity.SecurityPolicy;
import com.adaptivesecurity.api.entity.enums.AuditAction;
import com.adaptivesecurity.api.repository.SecurityPolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.OffsetDateTime;
import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class PolicyService {

    private static final Long POLICY_ID = 1L;

    private final SecurityPolicyRepository repository;
    private final AuditService auditService;

    @Value("${security.brute-force.warning-threshold:5}")
    private int defaultWarningThreshold;

    @Value("${security.brute-force.block-threshold:10}")
    private int defaultBlockThreshold;

    @Value("${security.brute-force.detection-window-minutes:60}")
    private int defaultDetectionWindowMinutes;

    @Value("${security.brute-force.auto-block-enabled:true}")
    private boolean defaultAutoBlockEnabled;

    @Value("${security.detectors.ssh-bruteforce.enabled:true}")
    private boolean defaultSshBruteforceEnabled;

    @Value("${security.detectors.ssh-probe.enabled:true}")
    private boolean defaultSshProbeEnabled;

    @Value("${security.detectors.port-scan.enabled:true}")
    private boolean defaultPortScanEnabled;

    @Value("${security.detectors.conn-flood.enabled:false}")
    private boolean defaultConnFloodEnabled;

    @Value("${security.detectors.port-scan.min-ports:5}")
    private int defaultPortScanMinPorts;

    @Value("${security.detectors.conn-flood.min-connections:50}")
    private int defaultConnFloodMinConnections;

    private volatile SecurityPolicy cache;

    @EventListener(ApplicationReadyEvent.class)
    public void warmUp() {
        ensureLoaded();
    }

    private SecurityPolicy ensureLoaded() {
        SecurityPolicy local = cache;
        if (local == null) {
            synchronized (this) {
                local = cache;
                if (local == null) {
                    local = repository.findById(POLICY_ID).orElseGet(this::createDefault);
                    cache = local;
                }
            }
        }
        return local;
    }

    private SecurityPolicy createDefault() {
        SecurityPolicy policy = SecurityPolicy.builder()
                .id(POLICY_ID)
                .warningThreshold(defaultWarningThreshold)
                .blockThreshold(defaultBlockThreshold)
                .detectionWindowMinutes(defaultDetectionWindowMinutes)
                .autoBlockEnabled(defaultAutoBlockEnabled)
                .sshBruteforceEnabled(defaultSshBruteforceEnabled)
                .sshProbeEnabled(defaultSshProbeEnabled)
                .portScanEnabled(defaultPortScanEnabled)
                .connFloodEnabled(defaultConnFloodEnabled)
                .portScanMinPorts(defaultPortScanMinPorts)
                .connFloodMinConnections(defaultConnFloodMinConnections)
                .updatedAt(OffsetDateTime.now())
                .updatedBy("system")
                .build();
        SecurityPolicy saved = repository.save(policy);
        log.info("Initialized default security policy: warning={}, block={}, window={}min, autoBlock={}",
                saved.getWarningThreshold(), saved.getBlockThreshold(),
                saved.getDetectionWindowMinutes(), saved.isAutoBlockEnabled());
        return saved;
    }

    public int warningThreshold() {
        return ensureLoaded().getWarningThreshold();
    }

    public int blockThreshold() {
        return ensureLoaded().getBlockThreshold();
    }

    public int detectionWindowMinutes() {
        return ensureLoaded().getDetectionWindowMinutes();
    }

    public boolean autoBlockEnabled() {
        return ensureLoaded().isAutoBlockEnabled();
    }

    public int portScanMinPorts() {
        return ensureLoaded().getPortScanMinPorts();
    }

    public int connFloodMinConnections() {
        return ensureLoaded().getConnFloodMinConnections();
    }

    public boolean detectorEnabled(String category) {
        SecurityPolicy policy = ensureLoaded();
        return switch (category) {
            case "SSH_BRUTEFORCE" -> policy.isSshBruteforceEnabled();
            case "SSH_PROBE" -> policy.isSshProbeEnabled();
            case "PORT_SCAN" -> policy.isPortScanEnabled();
            case "CONN_FLOOD" -> policy.isConnFloodEnabled();
            default -> true;
        };
    }

    public PolicyView current() {
        return PolicyView.from(ensureLoaded());
    }

    @Transactional
    public PolicyView update(PolicyUpdateRequest request, Actor actor) {
        if (request.getWarningThreshold() >= request.getBlockThreshold()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Warning threshold must be lower than block threshold");
        }

        SecurityPolicy policy = repository.findById(POLICY_ID).orElseGet(this::createDefault);
        String diff = describeDiff(policy, request);

        policy.setWarningThreshold(request.getWarningThreshold());
        policy.setBlockThreshold(request.getBlockThreshold());
        policy.setDetectionWindowMinutes(request.getDetectionWindowMinutes());
        policy.setAutoBlockEnabled(request.getAutoBlockEnabled());
        policy.setSshBruteforceEnabled(request.getSshBruteforceEnabled());
        policy.setSshProbeEnabled(request.getSshProbeEnabled());
        policy.setPortScanEnabled(request.getPortScanEnabled());
        policy.setConnFloodEnabled(request.getConnFloodEnabled());
        policy.setPortScanMinPorts(request.getPortScanMinPorts());
        policy.setConnFloodMinConnections(request.getConnFloodMinConnections());
        policy.setUpdatedAt(OffsetDateTime.now());
        policy.setUpdatedBy(actor.username());

        SecurityPolicy saved = repository.save(policy);
        cache = saved;

        auditService.log(AuditAction.CONFIG_CHANGE, actor, null,
                diff.isEmpty() ? "Policy saved (no field changes)" : diff);

        return PolicyView.from(saved);
    }

    @Transactional
    public PolicyView setPortKnocking(boolean enabled, Actor actor) {
        SecurityPolicy policy = repository.findById(POLICY_ID).orElseGet(this::createDefault);
        policy.setPortKnockingEnabled(enabled);
        policy.setSshBruteforceEnabled(!enabled);
        policy.setSshProbeEnabled(!enabled);
        policy.setUpdatedAt(OffsetDateTime.now());
        policy.setUpdatedBy(actor.username());

        SecurityPolicy saved = repository.save(policy);
        cache = saved;

        auditService.log(AuditAction.CONFIG_CHANGE, actor, null, enabled
                ? "Port knocking enabled (SSH detectors off, port 22 closed)"
                : "Port knocking disabled (SSH detectors on, port 22 open)");

        return PolicyView.from(saved);
    }

    private String describeDiff(SecurityPolicy current, PolicyUpdateRequest next) {
        StringBuilder sb = new StringBuilder();
        appendChange(sb, "warningThreshold", current.getWarningThreshold(), next.getWarningThreshold());
        appendChange(sb, "blockThreshold", current.getBlockThreshold(), next.getBlockThreshold());
        appendChange(sb, "detectionWindowMinutes", current.getDetectionWindowMinutes(), next.getDetectionWindowMinutes());
        appendChange(sb, "autoBlockEnabled", current.isAutoBlockEnabled(), next.getAutoBlockEnabled());
        appendChange(sb, "sshBruteforceEnabled", current.isSshBruteforceEnabled(), next.getSshBruteforceEnabled());
        appendChange(sb, "sshProbeEnabled", current.isSshProbeEnabled(), next.getSshProbeEnabled());
        appendChange(sb, "portScanEnabled", current.isPortScanEnabled(), next.getPortScanEnabled());
        appendChange(sb, "connFloodEnabled", current.isConnFloodEnabled(), next.getConnFloodEnabled());
        appendChange(sb, "portScanMinPorts", current.getPortScanMinPorts(), next.getPortScanMinPorts());
        appendChange(sb, "connFloodMinConnections", current.getConnFloodMinConnections(), next.getConnFloodMinConnections());
        return sb.toString();
    }

    private void appendChange(StringBuilder sb, String field, Object oldValue, Object newValue) {
        if (!Objects.equals(oldValue, newValue)) {
            if (!sb.isEmpty()) {
                sb.append("; ");
            }
            sb.append(field).append(": ").append(oldValue).append(" -> ").append(newValue);
        }
    }
}
