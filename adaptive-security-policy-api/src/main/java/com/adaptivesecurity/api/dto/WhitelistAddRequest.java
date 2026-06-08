package com.adaptivesecurity.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WhitelistAddRequest {

    @NotBlank(message = "IP address must not be blank")
    @Pattern(
        regexp = "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$",
        message = "Invalid IPv4 address (e.g. 192.168.1.1)"
    )
    private String ipAddress;

    @Size(max = 255, message = "Note must be at most 255 characters")
    private String note;
}
