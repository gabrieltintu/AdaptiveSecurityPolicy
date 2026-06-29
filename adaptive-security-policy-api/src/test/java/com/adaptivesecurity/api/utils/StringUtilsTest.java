package com.adaptivesecurity.api.utils;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class StringUtilsTest {

    @Test
    void fillsIptablesTemplate() {
        assertThat(StringUtils.formatString("sudo iptables %s INPUT -s %s -j DROP", "-A", "1.2.3.4"))
                .isEqualTo("sudo iptables -A INPUT -s 1.2.3.4 -j DROP");
    }

    @Test
    void fillsNumericPlaceholder() {
        assertThat(StringUtils.formatString("%d minutes ago", 60)).isEqualTo("60 minutes ago");
    }
}
