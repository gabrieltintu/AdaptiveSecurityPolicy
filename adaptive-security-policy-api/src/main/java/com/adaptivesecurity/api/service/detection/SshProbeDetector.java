package com.adaptivesecurity.api.service.detection;

import com.adaptivesecurity.api.service.CommandExecutorService;
import com.adaptivesecurity.api.utils.AppConstants;
import org.springframework.stereotype.Component;

@Component
public class SshProbeDetector extends LogPatternDetector {

    public SshProbeDetector(CommandExecutorService commandExecutor) {
        super(commandExecutor, AppConstants.FAILED_PASSWORD_IP_REGEX);
    }

    @Override
    public String category() {
        return "SSH_PROBE";
    }

    @Override
    protected String buildCommand(int windowMinutes) {
        return String.format(AppConstants.SSH_JOURNAL_CMD, windowMinutes) + " | grep \"Invalid user\"";
    }
}
