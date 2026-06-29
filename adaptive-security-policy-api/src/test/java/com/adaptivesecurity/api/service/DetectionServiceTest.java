package com.adaptivesecurity.api.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adaptivesecurity.api.dto.SuspiciousIpInfo;
import com.adaptivesecurity.api.service.detection.IpThreat;
import com.adaptivesecurity.api.service.detection.ThreatDetector;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class DetectionServiceTest {

    private final ThreatDetector d1 = mock(ThreatDetector.class);
    private final ThreatDetector d2 = mock(ThreatDetector.class);
    private final PolicyService policy = mock(PolicyService.class);
    private final DetectionService service = new DetectionService(List.of(d1, d2), policy);

    @Test
    void aggregatesScorePerIpAcrossDetectors() {
        when(policy.detectionWindowMinutes()).thenReturn(60);
        when(policy.detectorEnabled("A")).thenReturn(true);
        when(policy.detectorEnabled("B")).thenReturn(true);
        when(d1.category()).thenReturn("A");
        when(d2.category()).thenReturn("B");
        when(d1.detect(60)).thenReturn(Map.of("1.1.1.1", 3));
        when(d2.detect(60)).thenReturn(Map.of("1.1.1.1", 2, "2.2.2.2", 5));

        Map<String, IpThreat> result = service.detect();

        assertThat(result.get("1.1.1.1").totalCount()).isEqualTo(5);
        assertThat(result.get("2.2.2.2").totalCount()).isEqualTo(5);
        assertThat(result.get("1.1.1.1").categories()).containsExactlyInAnyOrder("A", "B");
    }

    @Test
    void skipsDetectorDisabledInPolicy() {
        when(policy.detectionWindowMinutes()).thenReturn(60);
        when(policy.detectorEnabled("A")).thenReturn(true);
        when(policy.detectorEnabled("B")).thenReturn(false);
        when(d1.category()).thenReturn("A");
        when(d2.category()).thenReturn("B");
        when(d1.detect(60)).thenReturn(Map.of("1.1.1.1", 3));

        Map<String, IpThreat> result = service.detect();

        assertThat(result.get("1.1.1.1").totalCount()).isEqualTo(3);
        assertThat(result).doesNotContainKey("2.2.2.2");
        verify(d2, never()).detect(anyInt());
    }

    @Test
    void suspiciousIpsOnlyAboveWarningThreshold() {
        when(policy.detectionWindowMinutes()).thenReturn(60);
        when(policy.warningThreshold()).thenReturn(3);
        when(policy.detectorEnabled("A")).thenReturn(true);
        when(policy.detectorEnabled("B")).thenReturn(true);
        when(d1.category()).thenReturn("A");
        when(d2.category()).thenReturn("B");
        when(d1.detect(60)).thenReturn(Map.of("1.1.1.1", 5));
        when(d2.detect(60)).thenReturn(Map.of("2.2.2.2", 1)); // below threshold

        List<SuspiciousIpInfo> suspicious = service.getSuspiciousIps(Set.of("1.1.1.1"));

        assertThat(suspicious).extracting(SuspiciousIpInfo::getIpAddress).containsExactly("1.1.1.1");
        assertThat(suspicious.get(0).getStatus()).isEqualTo("BLOCKED");
    }
}
