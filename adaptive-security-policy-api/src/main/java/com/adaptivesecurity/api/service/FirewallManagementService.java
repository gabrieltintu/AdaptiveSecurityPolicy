package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.FirewallActionResponse;
import com.adaptivesecurity.api.utils.AppConstants;
import com.adaptivesecurity.api.utils.StringUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class FirewallManagementService {

    private final CommandExecutorService commandExecutor;

    public FirewallActionResponse blockIp(String ipAddress, String chain) {
        List<String> commands = buildCommands("-A", ipAddress, chain);
        return executeAll(commands, "blocked", ipAddress);
    }

    public FirewallActionResponse unblockIp(String ipAddress, String chain) {
        List<String> commands = buildCommands("-D", ipAddress, chain);
        return executeAllIdempotent(commands, ipAddress);
    }

    /**
     * Port knocking — opens the protected port for a single IP by inserting an ACCEPT
     * rule at the top of INPUT (above the default DROP). Returns true on success.
     */
    public boolean openPort(String ipAddress, int port) {
        String cmd = StringUtils.formatString(AppConstants.IPTABLES_OPEN_PORT, ipAddress, port);
        String result = commandExecutor.execute(cmd);
        return !result.startsWith("Warning") && !result.startsWith("Internal error");
    }

    /**
     * Port knocking — removes the per-IP ACCEPT rule (best effort; a missing rule is harmless).
     * Established sessions survive thanks to the conntrack ESTABLISHED,RELATED rule.
     */
    public void closePort(String ipAddress, int port) {
        String cmd = StringUtils.formatString(AppConstants.IPTABLES_CLOSE_PORT, ipAddress, port);
        commandExecutor.execute(cmd);
    }

    private List<String> buildCommands(String action, String ipAddress, String chain) {
        List<String> commands = new ArrayList<>();
        if (chain.equals("INPUT") || chain.equals("ALL")) {
            commands.add(StringUtils.formatString(AppConstants.IPTABLES_INPUT_RULE, action, ipAddress));
        }
        if (chain.equals("OUTPUT") || chain.equals("ALL")) {
            commands.add(StringUtils.formatString(AppConstants.IPTABLES_OUTPUT_RULE, action, ipAddress));
        }
        if (chain.equals("FORWARD") || chain.equals("ALL")) {
            commands.add(StringUtils.formatString(AppConstants.IPTABLES_FORWARD_SRC, action, ipAddress));
            commands.add(StringUtils.formatString(AppConstants.IPTABLES_FORWARD_DST, action, ipAddress));
        }
        return commands;
    }

    private FirewallActionResponse executeAll(List<String> commands, String action, String ipAddress) {
        List<String> errors = new ArrayList<>();
        for (String cmd : commands) {
            String result = commandExecutor.execute(cmd);
            if (result.startsWith("Warning") || result.startsWith("Internal error")) {
                errors.add(result);
            }
        }
        boolean success = errors.isEmpty();
        String message = success
                ? "IP " + ipAddress + " has been " + action + " successfully on all specified chains."
                : "Partial failure for IP " + ipAddress + ": " + String.join("; ", errors);
        return FirewallActionResponse.builder().success(success).message(message).build();
    }

    /**
     * Like executeAll but tolerates "Bad rule" / "No chain" errors from iptables -D.
     * If the rule is already gone, the goal (IP not blocked) is achieved — treat as success.
     */
    private FirewallActionResponse executeAllIdempotent(List<String> commands, String ipAddress) {
        List<String> errors = new ArrayList<>();
        for (String cmd : commands) {
            String result = commandExecutor.execute(cmd);
            if ((result.startsWith("Warning") || result.startsWith("Internal error"))
                    && !result.contains("Bad rule")
                    && !result.contains("No chain/target/match")) {
                errors.add(result);
            }
        }
        boolean success = errors.isEmpty();
        String message = success
                ? "IP " + ipAddress + " has been unblocked successfully on all specified chains."
                : "Partial failure for IP " + ipAddress + ": " + String.join("; ", errors);
        return FirewallActionResponse.builder().success(success).message(message).build();
    }
}
