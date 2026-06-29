package com.adaptivesecurity.api.utils;

public final class AppConstants {

    private AppConstants() {
    }

    public static final int SUCCESS_EXIT_CODE = 0;

    // iptables command templates
    public static final String IPTABLES_INPUT_RULE   = "sudo iptables %s INPUT -s %s -j DROP";
    public static final String IPTABLES_OUTPUT_RULE  = "sudo iptables %s OUTPUT -d %s -j DROP";
    public static final String IPTABLES_FORWARD_SRC  = "sudo iptables %s FORWARD -s %s -j DROP";
    public static final String IPTABLES_FORWARD_DST  = "sudo iptables %s FORWARD -d %s -j DROP";

    // Port knocking — open/close a protected port for a single IP. %s = ip, %d = port
    // Open inserts at the top of INPUT (above the default DROP); close removes that rule.
    public static final String IPTABLES_OPEN_PORT    = "sudo iptables -I INPUT 1 -s %s -p tcp --dport %d -j ACCEPT";
    public static final String IPTABLES_CLOSE_PORT   = "sudo iptables -D INPUT -s %s -p tcp --dport %d -j ACCEPT";

    // Brute force detection — %d is replaced with the configurable detection window in minutes
    public static final String FAILED_PASSWORD_IP_REGEX  = "from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) port";

    // Multi-service detection — base journald commands (%d = detection window in minutes)
    public static final String SSH_JOURNAL_CMD       = "journalctl -u ssh -u sshd --since \"%d minutes ago\" --no-pager 2>/dev/null";
    public static final String KERNEL_LOG_CMD        = "journalctl -k --since \"%d minutes ago\" --no-pager 2>/dev/null";
    public static final String PORT_SCAN_LINE_REGEX  = "SRC=(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}).*DPT=(\\d{1,5})";

    // Connection flood detection — count established TCP connections per peer IP
    public static final String SS_ESTABLISHED_CMD    = "ss -tn state established 2>/dev/null";
    public static final String SS_PEER_IP_REGEX      = "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})";

    // Kill active connections of a blocked IP so blocking is immediate (%s = ip)
    public static final String SS_KILL_CMD           = "sudo ss -K dst %s";

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