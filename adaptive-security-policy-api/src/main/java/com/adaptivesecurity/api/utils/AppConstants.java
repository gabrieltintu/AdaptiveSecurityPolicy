package com.adaptivesecurity.api.utils;

public final class AppConstants {

    private AppConstants() {
        // Restrict instantiation
    }

    public static final int SUCCESS_EXIT_CODE = 0;

    // iptables command templates — use StringUtils.formatString() to populate
    // %1$s = action (-A to add, -D to delete), %2$s = ip address
    public static final String IPTABLES_INPUT_RULE   = "sudo iptables %s INPUT -s %s -j DROP";
    public static final String IPTABLES_OUTPUT_RULE  = "sudo iptables %s OUTPUT -d %s -j DROP";
    public static final String IPTABLES_FORWARD_SRC  = "sudo iptables %s FORWARD -s %s -j DROP";
    public static final String IPTABLES_FORWARD_DST  = "sudo iptables %s FORWARD -d %s -j DROP";

    // Brute force detection
    public static final String AUTH_LOG_CMD              = "grep \"Failed password\" /var/log/auth.log";
    public static final String FAILED_PASSWORD_IP_REGEX  = "from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) port";

    // Email subject templates (%s = ip address)
    public static final String WARNING_EMAIL_SUBJECT = "[Security Alert] Suspicious IP Detected: %s";
    public static final String BLOCK_EMAIL_SUBJECT   = "[Security Action] IP Automatically Blocked: %s";

    // Email body templates
    // WARNING: %s=ip, %d=attempts, %d=warningThreshold, %s=detectedAt, %d=blockThreshold, %s=consoleUrl
    public static final String WARNING_EMAIL_BODY =
            "A suspicious IP address has been detected attempting to access your server.\n\n" +
            "IP Address     : %s\n" +
            "Failed Attempts: %d\n" +
            "Warning Threshold : %d\n" +
            "Detected At    : %s\n\n" +
            "The IP has NOT been blocked yet.\n" +
            "If attempts continue, the system will automatically block it after %d failed attempts.\n\n" +
            "To manually block this IP, access the security console:\n%s";

    // BLOCK: %s=ip, %d=attempts, %d=blockThreshold, %s=blockedAt, %s=consoleUrl
    public static final String BLOCK_EMAIL_BODY =
            "The system has automatically blocked a malicious IP address.\n\n" +
            "IP Address     : %s\n" +
            "Failed Attempts: %d\n" +
            "Block Threshold: %d\n" +
            "Blocked At     : %s\n" +
            "Action         : BLOCKED on all chains (INPUT, OUTPUT, FORWARD)\n\n" +
            "To manually unblock this IP, access the security console:\n%s";
}