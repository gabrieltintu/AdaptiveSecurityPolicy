package com.adaptivesecurity.api.service.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adaptivesecurity.api.service.CommandExecutorService;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SshBruteForceDetectorTest {

    private final CommandExecutorService executor = mock(CommandExecutorService.class);
    private final SshBruteForceDetector detector = new SshBruteForceDetector(executor);

    @Test
    void hasExpectedCategory() {
        assertThat(detector.category()).isEqualTo("SSH_BRUTEFORCE");
    }

    @Test
    void countsFailedPasswordsPerIp() {
        when(executor.execute(anyString())).thenReturn(
                "Jun 27 10:00:01 host sshd[1]: Failed password for root from 203.0.113.5 port 51000 ssh2\n" +
                "Jun 27 10:00:02 host sshd[2]: Failed password for admin from 203.0.113.5 port 51001 ssh2\n" +
                "Jun 27 10:00:03 host sshd[3]: Failed password for root from 198.51.100.7 port 40000 ssh2");

        Map<String, Integer> result = detector.detect(60);

        assertThat(result).hasSize(2)
                .containsEntry("203.0.113.5", 2)
                .containsEntry("198.51.100.7", 1);
    }

    @Test
    void returnsEmptyWhenCommandFails() {
        when(executor.execute(anyString())).thenReturn("Warning (Code 1): journalctl failed");
        assertThat(detector.detect(60)).isEmpty();
    }

    @Test
    void returnsEmptyOnBlankOutput() {
        when(executor.execute(anyString())).thenReturn("");
        assertThat(detector.detect(60)).isEmpty();
    }
}
