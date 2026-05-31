package com.adaptivesecurity.api.service;

import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * State machine for port knocking. Receives knock events from {@link KnockListenerService}
 * and, when an IP completes the secret port sequence in order within the timeout, opens the
 * protected port for that IP for a limited window.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PortKnockingService {

    private final FirewallManagementService firewallManagementService;
    private final WebSocketAlertService webSocketAlertService;

    @Value("${security.port-knocking.sequence}")
    private int[] sequence;

    @Value("${security.port-knocking.protected-port}")
    private int protectedPort;

    @Value("${security.port-knocking.timeout-ms}")
    private long timeoutMs;

    @Value("${security.port-knocking.open-duration-seconds}")
    private long openDurationSeconds;

    // Per-IP progress through the knock sequence
    private final Map<String, KnockState> progress = new ConcurrentHashMap<>();
    private final ScheduledExecutorService closeScheduler = Executors.newSingleThreadScheduledExecutor();

    /**
     * Called by the listeners every time an IP connects to one of the knock ports.
     * Advances the IP's position in the secret sequence; opens the protected port when
     * the full sequence is completed in order within the timeout. Any wrong port resets
     * progress (but a knock on the first port immediately restarts the sequence).
     */
    public synchronized void handleKnock(String ip, int port) {
        long now = System.currentTimeMillis();
        KnockState state = progress.computeIfAbsent(ip, k -> new KnockState());

        // Reset if the previous knock in this sequence is too old
        if (state.step > 0 && (now - state.lastKnockTime) > timeoutMs) {
            state.reset();
        }

        if (port == sequence[state.step]) {
            state.step++;
            state.lastKnockTime = now;
            log.debug("Knock {}/{} from {} (port {})", state.step, sequence.length, ip, port);

            if (state.step == sequence.length) {
                progress.remove(ip);
                openAccess(ip);
            }
        } else {
            // Wrong port → reset, but allow an immediate restart if it was the first port
            state.reset();
            if (port == sequence[0]) {
                state.step = 1;
                state.lastKnockTime = now;
            }
        }
    }

    private void openAccess(String ip) {
        boolean ok = firewallManagementService.openPort(ip, protectedPort);
        if (ok) {
            log.info("Port knocking SUCCESS — opened port {} for {} ({}s window)", protectedPort, ip, openDurationSeconds);
            webSocketAlertService.sendPortKnockAlert(ip, protectedPort);
            closeScheduler.schedule(() -> {
                firewallManagementService.closePort(ip, protectedPort);
                log.info("Port {} re-closed for {}", protectedPort, ip);
            }, openDurationSeconds, TimeUnit.SECONDS);
        } else {
            log.warn("Port knocking — failed to open port {} for {}", protectedPort, ip);
        }
    }

    @PreDestroy
    public void shutdown() {
        closeScheduler.shutdownNow();
    }

    /** Per-IP progress tracker through the knock sequence. */
    private static class KnockState {
        private int step;
        private long lastKnockTime;

        void reset() {
            step = 0;
            lastKnockTime = 0;
        }
    }
}
