package com.adaptivesecurity.api.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adaptivesecurity.api.dto.PolicyUpdateRequest;
import com.adaptivesecurity.api.dto.PolicyView;
import com.adaptivesecurity.api.entity.SecurityPolicy;
import com.adaptivesecurity.api.repository.SecurityPolicyRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class PolicyServiceTest {

    private final SecurityPolicyRepository repository = mock(SecurityPolicyRepository.class);
    private final AuditService auditService = mock(AuditService.class);
    private final PolicyService service = new PolicyService(repository, auditService);

    private PolicyUpdateRequest request(int warning, int block) {
        return request(warning, block, 5, 50);
    }

    private PolicyUpdateRequest request(int warning, int block, int minPorts, int minConnections) {
        PolicyUpdateRequest r = new PolicyUpdateRequest();
        r.setWarningThreshold(warning);
        r.setBlockThreshold(block);
        r.setDetectionWindowMinutes(60);
        r.setAutoBlockEnabled(true);
        r.setSshBruteforceEnabled(true);
        r.setSshProbeEnabled(true);
        r.setPortScanEnabled(true);
        r.setConnFloodEnabled(false);
        r.setPortScanMinPorts(minPorts);
        r.setConnFloodMinConnections(minConnections);
        return r;
    }

    @Test
    void rejectsWarningThresholdNotBelowBlock() {
        assertThatThrownBy(() -> service.update(request(10, 5), Actor.system()))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void updatesPolicyWhenValid() {
        SecurityPolicy existing = SecurityPolicy.builder()
                .id(1L).warningThreshold(3).blockThreshold(6).detectionWindowMinutes(60).build();
        when(repository.findById(1L)).thenReturn(Optional.of(existing));
        when(repository.save(any(SecurityPolicy.class))).thenAnswer(i -> i.getArgument(0));

        PolicyView view = service.update(request(4, 9, 8, 100), Actor.system());

        assertThat(view.warningThreshold()).isEqualTo(4);
        assertThat(view.blockThreshold()).isEqualTo(9);
        assertThat(view.portScanMinPorts()).isEqualTo(8);
        assertThat(view.connFloodMinConnections()).isEqualTo(100);
        verify(repository).save(any(SecurityPolicy.class));
    }

    @Test
    void detectorEnabledReflectsPolicyFlags() {
        SecurityPolicy policy = SecurityPolicy.builder()
                .id(1L).warningThreshold(3).blockThreshold(6).detectionWindowMinutes(60)
                .sshBruteforceEnabled(true).portScanEnabled(true).connFloodEnabled(false)
                .portScanMinPorts(7).connFloodMinConnections(40).build();
        when(repository.findById(1L)).thenReturn(Optional.of(policy));

        assertThat(service.detectorEnabled("PORT_SCAN")).isTrue();
        assertThat(service.detectorEnabled("CONN_FLOOD")).isFalse();
        assertThat(service.detectorEnabled("UNKNOWN")).isTrue(); // default-allow
        assertThat(service.portScanMinPorts()).isEqualTo(7);
        assertThat(service.connFloodMinConnections()).isEqualTo(40);
    }
}
