package com.adaptivesecurity.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class FirewallActionResponse {
    private boolean success;
    private String message;
}
