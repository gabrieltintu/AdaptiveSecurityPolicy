package com.adaptivesecurity.api.service.detection;

import com.adaptivesecurity.api.service.CommandExecutorService;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class LogPatternDetector implements ThreatDetector {

    private final CommandExecutorService commandExecutor;
    private final Pattern ipPattern;

    protected LogPatternDetector(CommandExecutorService commandExecutor, String ipRegex) {
        this.commandExecutor = commandExecutor;
        this.ipPattern = Pattern.compile(ipRegex);
    }

    protected abstract String buildCommand(int windowMinutes);

    @Override
    public Map<String, Integer> detect(int windowMinutes) {
        Map<String, Integer> attempts = new HashMap<>();
        String output = commandExecutor.execute(buildCommand(windowMinutes));
        if (output == null || output.isBlank()
                || output.startsWith("Warning") || output.startsWith("Internal error")) {
            return attempts;
        }
        for (String line : output.split("\n")) {
            Matcher matcher = ipPattern.matcher(line);
            if (matcher.find()) {
                attempts.merge(matcher.group(1), 1, Integer::sum);
            }
        }
        return attempts;
    }
}
