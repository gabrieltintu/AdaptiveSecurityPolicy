package com.adaptivesecurity.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class FirewallActionRequest {

    @NotBlank(message = "IP address must not be blank")
    @Pattern(
        regexp = "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)(/([0-9]|[1-2][0-9]|3[0-2]))?$",
        message = "Invalid IPv4 address or CIDR notation (e.g. 192.168.1.1 or 192.168.1.0/24)"
    )
    private String ipAddress;

    @Pattern(
        regexp = "^(INPUT|OUTPUT|FORWARD|ALL)$",
        message = "Chain must be INPUT, OUTPUT, FORWARD, or ALL"
    )
    private String chain = "ALL";
}
