package com.adaptivesecurity.api.service.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adaptivesecurity.api.service.CommandExecutorService;
import com.adaptivesecurity.api.service.PolicyService;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class PortScanDetectorTest {

    private final CommandExecutorService executor = mock(CommandExecutorService.class);
    private final PolicyService policyService = mock(PolicyService.class);
    private final PortScanDetector detector = new PortScanDetector(executor, policyService);

    PortScanDetectorTest() {
        ReflectionTestUtils.setField(detector, "logPrefix", "ASP-SCAN");
    }

    @Test
    void hasExpectedCategory() {
        assertThat(detector.category()).isEqualTo("PORT_SCAN");
    }

    @Test
    void flagsIpHittingAtLeastMinDistinctPorts() {
        when(policyService.portScanMinPorts()).thenReturn(5);
        when(executor.execute(anyString())).thenReturn(
                "kernel: ASP-SCAN SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=22\n" +
                "kernel: ASP-SCAN SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=23\n" +
                "kernel: ASP-SCAN SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=80\n" +
                "kernel: ASP-SCAN SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=443\n" +
                "kernel: ASP-SCAN SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=3306\n" +
                "kernel: ASP-SCAN SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=22\n" +
                "kernel: ASP-SCAN SRC=198.51.100.7 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=22");

        Map<String, Integer> result = detector.detect(60);

        assertThat(result).containsEntry("203.0.113.5", 5); // 5 distinct ports (duplicate 22 ignored)
        assertThat(result).doesNotContainKey("198.51.100.7"); // only 1 port → below threshold
    }

    @Test
    void returnsEmptyWhenCommandFails() {
        when(executor.execute(anyString())).thenReturn("Warning (Code 1): no kernel log");
        assertThat(detector.detect(60)).isEmpty();
    }
}
