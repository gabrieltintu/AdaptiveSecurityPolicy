package com.adaptivesecurity.api.utils;

public final class AppConstants {

    private AppConstants() {
        // Restrict instantiation
    }

    public static final int SUCCESS_EXIT_CODE = 0;

    // iptables command templates — use StringUtils.formatString() to populate
    // %1$s = action (-A to add, -D to delete)
    // %2$s = ip address
    public static final String IPTABLES_INPUT_RULE   = "sudo iptables %s INPUT -s %s -j DROP";
    public static final String IPTABLES_OUTPUT_RULE  = "sudo iptables %s OUTPUT -d %s -j DROP";
    public static final String IPTABLES_FORWARD_SRC  = "sudo iptables %s FORWARD -s %s -j DROP";
    public static final String IPTABLES_FORWARD_DST  = "sudo iptables %s FORWARD -d %s -j DROP";
}