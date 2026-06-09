package com.adaptivesecurity.api.service.detection;

import com.adaptivesecurity.api.service.CommandExecutorService;
import com.adaptivesecurity.api.utils.AppConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class PortScanDetector implements ThreatDetector {

    private static final Pattern SCAN_PATTERN = Pattern.compile(AppConstants.PORT_SCAN_LINE_REGEX);

    private final CommandExecutorService commandExecutor;

    @Value("${security.detectors.port-scan.log-prefix:ASP-SCAN}")
    private String logPrefix;

    @Value("${security.detectors.port-scan.min-ports:5}")
    private int minPorts;

    public PortScanDetector(CommandExecutorService commandExecutor) {
        this.commandExecutor = commandExecutor;
    }

    @Override
    public String category() {
        return "PORT_SCAN";
    }

    @Override
    public Map<String, Integer> detect(int windowMinutes) {
        Map<String, Integer> result = new HashMap<>();
        String command = String.format(AppConstants.KERNEL_LOG_CMD, windowMinutes) + " | grep \"" + logPrefix + "\"";
        String output = commandExecutor.execute(command);
        if (output == null || output.isBlank()
                || output.startsWith("Warning") || output.startsWith("Internal error")) {
            return result;
        }

        Map<String, Set<String>> portsByIp = new HashMap<>();
        for (String line : output.split("\n")) {
            Matcher matcher = SCAN_PATTERN.matcher(line);
            if (matcher.find()) {
                portsByIp.computeIfAbsent(matcher.group(1), k -> new HashSet<>()).add(matcher.group(2));
            }
        }

        for (Map.Entry<String, Set<String>> entry : portsByIp.entrySet()) {
            int distinctPorts = entry.getValue().size();
            if (distinctPorts >= minPorts) {
                result.put(entry.getKey(), distinctPorts);
            }
        }
        return result;
    }
}
