package com.adaptivesecurity.api.utils;

public final class StringUtils {

    private StringUtils() {
    }

    public static String formatString(String template, Object... args) {
        return String.format(template, args);
    }
}
