package com.adaptivesecurity.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class FirewallRule {
    private String chain;       // INPUT, FORWARD, OUTPUT
    private String packets;     // Numarul de pachete care au lovit regula
    private String bytes;       // Volumul de date
    private String target;      // ACCEPT, DROP, REJECT
    private String protocol;    // tcp, udp, icmp, all
    private String source;      // IP sursa
    private String destination; // IP destinatie
    private String options;     // Detalii extra (ex: porturi)
}