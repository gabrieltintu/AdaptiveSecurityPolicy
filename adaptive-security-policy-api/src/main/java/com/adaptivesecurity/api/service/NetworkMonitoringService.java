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

    // Metoda veche pentru conexiuni (ramane neschimbata)
    public List<NetworkConnection> getActiveConnections() {
        String rawOutput = commandExecutor.execute("ss -tuln");
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

    // NOU: Metoda pentru citirea si parsarea regulilor de Firewall
    public List<FirewallRule> getFirewallRules() {
        // Folosim sudo pentru ca iptables cere drepturi de root
        String rawOutput = commandExecutor.execute("sudo iptables -L -n -v");
        List<FirewallRule> rules = new ArrayList<>();

        if (rawOutput == null || rawOutput.isEmpty()) return rules;

        String[] lines = rawOutput.split("\n");
        String currentChain = "";

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            // Detectam in ce "Chain" suntem (INPUT, FORWARD, OUTPUT)
            if (line.startsWith("Chain")) {
                currentChain = line.split(" ")[1];
                continue;
            }

            // Sarim peste liniile de header ale tabelului
            if (line.startsWith("pkts") || line.startsWith("num")) continue;

            // Parsam liniile de date
            String[] parts = line.split("\\s+");
            if (parts.length >= 9) {
                // Structura iptables -v: [0]pkts, [1]bytes, [2]target, [3]prot, [4]opt, [5]in, [6]out, [7]source, [8]destination
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