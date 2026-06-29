package com.adaptivesecurity.api.service.detection;

import com.adaptivesecurity.api.service.CommandExecutorService;
import com.adaptivesecurity.api.service.PolicyService;
import com.adaptivesecurity.api.utils.AppConstants;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class ConnectionFloodDetector implements ThreatDetector {

    private static final Pattern PEER_PATTERN = Pattern.compile(AppConstants.SS_PEER_IP_REGEX);

    private final CommandExecutorService commandExecutor;
    private final PolicyService policyService;

    public ConnectionFloodDetector(CommandExecutorService commandExecutor, PolicyService policyService) {
        this.commandExecutor = commandExecutor;
        this.policyService = policyService;
    }

    @Override
    public String category() {
        return "CONN_FLOOD";
    }

    @Override
    public Map<String, Integer> detect(int windowMinutes) {
        Map<String, Integer> result = new HashMap<>();
        String output = commandExecutor.execute(AppConstants.SS_ESTABLISHED_CMD);
        if (output == null || output.isBlank()
                || output.startsWith("Warning") || output.startsWith("Internal error")) {
            return result;
        }

        Map<String, Integer> perIp = new HashMap<>();
        for (String line : output.split("\n")) {
            Matcher matcher = PEER_PATTERN.matcher(line);
            String peer = null;
            while (matcher.find()) {
                peer = matcher.group(1);
            }
            if (peer != null && !peer.startsWith("127.")) {
                perIp.merge(peer, 1, Integer::sum);
            }
        }

        int minConnections = policyService.connFloodMinConnections();
        for (Map.Entry<String, Integer> entry : perIp.entrySet()) {
            if (entry.getValue() >= minConnections) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }
}
