package com.adaptivesecurity.api.service.detection;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class IpThreatTest {

    @Test
    void emptyByDefault() {
        IpThreat t = new IpThreat();
        assertThat(t.totalCount()).isZero();
        assertThat(t.categories()).isEmpty();
    }

    @Test
    void sumsSignalsAndKeepsCategoriesInOrder() {
        IpThreat t = new IpThreat();
        t.addSignal("SSH_BRUTEFORCE", 3);
        t.addSignal("PORT_SCAN", 5);
        assertThat(t.totalCount()).isEqualTo(8);
        assertThat(t.categories()).containsExactly("SSH_BRUTEFORCE", "PORT_SCAN");
    }

    @Test
    void sameCategoryCountedOnceButSummed() {
        IpThreat t = new IpThreat();
        t.addSignal("SSH_BRUTEFORCE", 2);
        t.addSignal("SSH_BRUTEFORCE", 4);
        assertThat(t.totalCount()).isEqualTo(6);
        assertThat(t.categories()).containsExactly("SSH_BRUTEFORCE");
    }
}
