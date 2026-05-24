package com.adaptivesecurity.api.utils;

public final class StringUtils {

    private StringUtils() {
        // Restrict instantiation
    }

    /**
     * Populates a template string with the given arguments.
     * Uses standard %s placeholders.
     *
     * Example:
     *   formatString("sudo iptables %s INPUT -s %s -j DROP", "-A", "1.2.3.4")
     *   → "sudo iptables -A INPUT -s 1.2.3.4 -j DROP"
     */
    public static String formatString(String template, Object... args) {
        return String.format(template, args);
    }
}
