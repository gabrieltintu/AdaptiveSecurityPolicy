package com.adaptivesecurity.api.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adaptivesecurity.api.dto.ProposedAction;
import com.adaptivesecurity.api.service.GeminiClient.RawAction;
import java.util.List;
import org.junit.jupiter.api.Test;

class AiPolicyServiceTest {

    private final GeminiClient gemini = mock(GeminiClient.class);
    private final AiPolicyService service = new AiPolicyService(gemini);

    private ProposedAction interpretFirst(RawAction raw) {
        when(gemini.interpret("req")).thenReturn(List.of(raw));
        return service.interpret("req").get(0);
    }

    @Test
    void acceptsValidBlock() {
        ProposedAction a = interpretFirst(new RawAction("BLOCK", "203.0.113.5", "ALL", null));
        assertThat(a.valid()).isTrue();
        assertThat(a.action()).isEqualTo("BLOCK");
        assertThat(a.chain()).isEqualTo("ALL");
    }

    @Test
    void rejectsUnknownAction() {
        ProposedAction a = interpretFirst(new RawAction("NUKE", "1.2.3.4", "ALL", null));
        assertThat(a.valid()).isFalse();
        assertThat(a.error()).isEqualTo("Unknown action");
    }

    @Test
    void rejectsInvalidIp() {
        ProposedAction a = interpretFirst(new RawAction("BLOCK", "999.1.1.1", "ALL", null));
        assertThat(a.valid()).isFalse();
        assertThat(a.error()).contains("Invalid IP");
    }

    @Test
    void rejectsInvalidChain() {
        ProposedAction a = interpretFirst(new RawAction("BLOCK", "1.2.3.4", "WRONG", null));
        assertThat(a.valid()).isFalse();
        assertThat(a.error()).isEqualTo("Invalid chain");
    }

    @Test
    void acceptsCidrAndNormalizesLowercase() {
        ProposedAction a = interpretFirst(new RawAction("block", "10.0.0.0/24", "input", null));
        assertThat(a.valid()).isTrue();
        assertThat(a.action()).isEqualTo("BLOCK");
        assertThat(a.chain()).isEqualTo("INPUT");
    }

    @Test
    void whitelistHasNoChain() {
        ProposedAction a = interpretFirst(new RawAction("WHITELIST", "1.2.3.4", null, "trusted host"));
        assertThat(a.valid()).isTrue();
        assertThat(a.chain()).isNull();
    }
}
