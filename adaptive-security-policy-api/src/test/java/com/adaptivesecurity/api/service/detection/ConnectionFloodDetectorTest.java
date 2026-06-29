package com.adaptivesecurity.api.service.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adaptivesecurity.api.service.CommandExecutorService;
import com.adaptivesecurity.api.service.PolicyService;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ConnectionFloodDetectorTest {

    private final CommandExecutorService executor = mock(CommandExecutorService.class);
    private final PolicyService policyService = mock(PolicyService.class);
    private final ConnectionFloodDetector detector = new ConnectionFloodDetector(executor, policyService);

    @Test
    void hasExpectedCategory() {
        assertThat(detector.category()).isEqualTo("CONN_FLOOD");
    }

    @Test
    void flagsPeerWithManySimultaneousConnectionsAndSkipsLoopback() {
        when(policyService.connFloodMinConnections()).thenReturn(3);
        when(executor.execute(anyString())).thenReturn(
                "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n" +
                "ESTAB  0      0      192.168.1.10:8090   203.0.113.5:5000\n" +
                "ESTAB  0      0      192.168.1.10:8090   203.0.113.5:5001\n" +
                "ESTAB  0      0      192.168.1.10:8090   203.0.113.5:5002\n" +
                "ESTAB  0      0      192.168.1.10:8090   203.0.113.5:5003\n" +
                "ESTAB  0      0      192.168.1.10:8090   198.51.100.7:6000\n" +
                "ESTAB  0      0      127.0.0.1:5432      127.0.0.1:33000");

        Map<String, Integer> result = detector.detect(60);

        assertThat(result).containsEntry("203.0.113.5", 4); // >= 3 connections
        assertThat(result).doesNotContainKey("198.51.100.7"); // 1 connection
        assertThat(result).doesNotContainKey("127.0.0.1"); // loopback skipped
    }

    @Test
    void returnsEmptyWhenCommandFails() {
        when(executor.execute(anyString())).thenReturn("Warning (Code 1): ss missing");
        assertThat(detector.detect(60)).isEmpty();
    }
}
