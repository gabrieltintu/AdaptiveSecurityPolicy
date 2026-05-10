package com.adaptivesecurity.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NetworkConnection {
    private String protocol;      // ex: tcp, udp
    private String state;         // ex: LISTEN, ESTAB
    private String localAddress;  // Adresa locala si portul (ex: 0.0.0.0:8090)
    private String peerAddress;   // Adresa sursa (cine se conecteaza la tine)
}