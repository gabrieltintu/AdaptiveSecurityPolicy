package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.FirewallRule;
import com.adaptivesecurity.api.dto.NetworkConnection;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class NetworkMonitoringService {

    private final CommandExecutorService commandExecutor;

    public List<NetworkConnection> getActiveConnections() {
        String rawOutput = commandExecutor.execute("ss -tun");
        List<NetworkConnection> connections = new ArrayList<>();
        if (rawOutput == null || rawOutput.isEmpty()) return connections;

        String[] lines = rawOutput.split("\n");
        for (int i = 1; i < lines.length; i++) {
            String[] parts = lines[i].trim().split("\\s+");
            if (parts.length >= 6) {
                connections.add(NetworkConnection.builder()
                        .protocol(parts[0]).state(parts[1])
                        .localAddress(parts[4]).peerAddress(parts[5]).build());
            }
        }
        return connections;
    }

    // read and parse firewall rules from iptables
    public List<FirewallRule> getFirewallRules() {
        String rawOutput = commandExecutor.execute("sudo iptables -L -n -v");
        List<FirewallRule> rules = new ArrayList<>();

        if (rawOutput == null || rawOutput.isEmpty()) return rules;

        String[] lines = rawOutput.split("\n");
        String currentChain = "";

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            if (line.startsWith("Chain")) {
                currentChain = line.split(" ")[1];
                continue;
            }

            if (line.startsWith("pkts") || line.startsWith("num")) continue;

            String[] parts = line.split("\\s+");
            if (parts.length >= 9) {
                StringBuilder extraOptions = new StringBuilder();
                if (parts.length > 9) {
                    for (int j = 9; j < parts.length; j++) {
                        extraOptions.append(parts[j]).append(" ");
                    }
                }

                rules.add(FirewallRule.builder()
                        .chain(currentChain)
                        .packets(parts[0])
                        .bytes(parts[1])
                        .target(parts[2])
                        .protocol(parts[3])
                        .source(parts[7])
                        .destination(parts[8])
                        .options(extraOptions.toString().trim())
                        .build());
            }
        }
        return rules;
    }
}