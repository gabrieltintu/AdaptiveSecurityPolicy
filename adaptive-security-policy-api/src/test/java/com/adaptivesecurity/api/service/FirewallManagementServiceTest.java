package com.adaptivesecurity.api.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adaptivesecurity.api.dto.FirewallActionResponse;
import org.junit.jupiter.api.Test;

class FirewallManagementServiceTest {

    private final CommandExecutorService executor = mock(CommandExecutorService.class);
    private final FirewallManagementService service = new FirewallManagementService(executor);

    @Test
    void blockAllChainsThenDropsActiveSockets() {
        when(executor.execute(anyString())).thenReturn(""); // success

        FirewallActionResponse response = service.blockIp("1.2.3.4", "ALL");

        assertThat(response.isSuccess()).isTrue();
        verify(executor).execute("sudo iptables -A INPUT -s 1.2.3.4 -j DROP");
        verify(executor).execute("sudo iptables -A OUTPUT -d 1.2.3.4 -j DROP");
        verify(executor).execute("sudo iptables -A FORWARD -s 1.2.3.4 -j DROP");
        verify(executor).execute("sudo iptables -A FORWARD -d 1.2.3.4 -j DROP");
        verify(executor).execute("sudo ss -K dst 1.2.3.4");
    }

    @Test
    void failedBlockDoesNotDropSockets() {
        when(executor.execute(anyString())).thenReturn("Warning (Code 1): permission denied");

        FirewallActionResponse response = service.blockIp("1.2.3.4", "ALL");

        assertThat(response.isSuccess()).isFalse();
        verify(executor, never()).execute("sudo ss -K dst 1.2.3.4");
    }

    @Test
    void singleChainBlockOnlyTouchesThatChain() {
        when(executor.execute(anyString())).thenReturn("");

        service.blockIp("1.2.3.4", "INPUT");

        verify(executor).execute("sudo iptables -A INPUT -s 1.2.3.4 -j DROP");
        verify(executor, never()).execute("sudo iptables -A OUTPUT -d 1.2.3.4 -j DROP");
    }

    @Test
    void unblockIsIdempotentWhenRuleMissing() {
        when(executor.execute(anyString()))
                .thenReturn("Warning (Code 1): iptables: Bad rule (does a matching rule exist in that chain?).");

        FirewallActionResponse response = service.unblockIp("1.2.3.4", "ALL");

        assertThat(response.isSuccess()).isTrue();
    }
}
