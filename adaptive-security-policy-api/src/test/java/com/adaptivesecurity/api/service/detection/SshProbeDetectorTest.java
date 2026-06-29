package com.adaptivesecurity.api.service.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adaptivesecurity.api.service.CommandExecutorService;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SshProbeDetectorTest {

    private final CommandExecutorService executor = mock(CommandExecutorService.class);
    private final SshProbeDetector detector = new SshProbeDetector(executor);

    @Test
    void hasExpectedCategory() {
        assertThat(detector.category()).isEqualTo("SSH_PROBE");
    }

    @Test
    void countsInvalidUserAttemptsPerIp() {
        when(executor.execute(anyString())).thenReturn(
                "Jun 27 10:00:01 host sshd[1]: Invalid user oracle from 203.0.113.5 port 4000\n" +
                "Jun 27 10:00:02 host sshd[2]: Invalid user test from 203.0.113.5 port 4001\n" +
                "Jun 27 10:00:03 host sshd[3]: Invalid user admin from 192.0.2.9 port 4002");

        Map<String, Integer> result = detector.detect(60);

        assertThat(result).hasSize(2)
                .containsEntry("203.0.113.5", 2)
                .containsEntry("192.0.2.9", 1);
    }

    @Test
    void returnsEmptyWhenCommandFails() {
        when(executor.execute(anyString())).thenReturn("Internal error executing command: boom");
        assertThat(detector.detect(60)).isEmpty();
    }
}
