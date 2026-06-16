package com.adaptivesecurity.api.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PolicyUpdateRequest {

    @NotNull(message = "Warning threshold is required")
    @Min(value = 1, message = "Warning threshold must be at least 1")
    private Integer warningThreshold;

    @NotNull(message = "Block threshold is required")
    @Min(value = 1, message = "Block threshold must be at least 1")
    private Integer blockThreshold;

    @NotNull(message = "Detection window is required")
    @Min(value = 1, message = "Detection window must be at least 1 minute")
    private Integer detectionWindowMinutes;

    @NotNull(message = "Auto-block flag is required")
    private Boolean autoBlockEnabled;

    @NotNull(message = "SSH brute-force detector flag is required")
    private Boolean sshBruteforceEnabled;

    @NotNull(message = "SSH probe detector flag is required")
    private Boolean sshProbeEnabled;

    @NotNull(message = "Port scan detector flag is required")
    private Boolean portScanEnabled;

    @NotNull(message = "Connection flood detector flag is required")
    private Boolean connFloodEnabled;
}
