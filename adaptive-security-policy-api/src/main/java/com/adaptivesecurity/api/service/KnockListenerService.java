package com.adaptivesecurity.api.service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Opens a lightweight TCP listener on each knock port at startup. Every incoming connection
 * is recorded as a "knock" (source IP + port) and forwarded to {@link PortKnockingService};
 * the connection is closed immediately since nothing is served.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KnockListenerService {

    private static final String IPV4_MAPPED_PREFIX = "::ffff:";

    private final PortKnockingService portKnockingService;

    @Value("${security.port-knocking.enabled}")
    private boolean enabled;

    @Value("${security.port-knocking.sequence}")
    private int[] sequence;

    private final List<ServerSocket> serverSockets = new ArrayList<>();
    private ExecutorService listenerPool;

    @PostConstruct
    public void start() {
        if (!enabled) {
            log.info("Port knocking is disabled (security.port-knocking.enabled=false)");
            return;
        }
        listenerPool = Executors.newCachedThreadPool();
        for (int port : sequence) {
            try {
                ServerSocket serverSocket = new ServerSocket(port);
                serverSockets.add(serverSocket);
                listenerPool.submit(() -> listen(serverSocket, port));
                log.info("Knock listener started on port {}", port);
            } catch (IOException e) {
                log.error("Could not open knock listener on port {} — {}", port, e.getMessage());
            }
        }
    }

    private void listen(ServerSocket serverSocket, int port) {
        while (!serverSocket.isClosed()) {
            try (Socket client = serverSocket.accept()) {
                String ip = normalize(client.getInetAddress().getHostAddress());
                portKnockingService.handleKnock(ip, port);
            } catch (IOException e) {
                if (!serverSocket.isClosed()) {
                    log.warn("Knock accept error on port {} — {}", port, e.getMessage());
                }
            }
        }
    }

    /** Strips the IPv4-mapped IPv6 prefix so the IP matches IPv4 iptables rules. */
    private String normalize(String ip) {
        return ip.startsWith(IPV4_MAPPED_PREFIX) ? ip.substring(IPV4_MAPPED_PREFIX.length()) : ip;
    }

    @PreDestroy
    public void stop() {
        for (ServerSocket ss : serverSockets) {
            try {
                ss.close();
            } catch (IOException ignored) {
                // closing on shutdown — nothing to recover
            }
        }
        if (listenerPool != null) {
            listenerPool.shutdownNow();
        }
    }
}
