package com.adaptivesecurity.api.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class GeminiClient {

    private static final String SYSTEM_PROMPT =
            "You translate a network administrator's natural-language request into concrete firewall actions "
            + "for an adaptive security system. Allowed actions: BLOCK or UNBLOCK an IPv4 address or CIDR on an "
            + "iptables chain (ALL, INPUT, OUTPUT, FORWARD; default ALL); WHITELIST an IPv4 address or CIDR so it "
            + "is never auto-blocked. Only output actions explicitly implied by the request, using exact IPv4 or "
            + "CIDR notation. If the request is unrelated to firewall management or contains no valid IP, return "
            + "an empty actions array.";

    private final RestClient restClient;
    private final ObjectMapper objectMapper;
    private final String apiKey;
    private final String model;

    public GeminiClient(
            @Value("${gemini.base-url}") String baseUrl,
            @Value("${gemini.api-key:}") String apiKey,
            @Value("${gemini.model}") String model,
            ObjectMapper objectMapper) {
        this.restClient = RestClient.builder().baseUrl(baseUrl).build();
        this.apiKey = apiKey;
        this.model = model;
        this.objectMapper = objectMapper;
    }

    public List<RawAction> interpret(String text) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("GEMINI_API_KEY is not configured on the server");
        }
        try {
            String response = restClient.post()
                    .uri("/v1beta/models/{model}:generateContent", model)
                    .header("x-goog-api-key", apiKey)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(buildRequest(text))
                    .retrieve()
                    .body(String.class);
            return parse(response);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Gemini request failed", e);
            throw new IllegalStateException("AI service request failed: " + e.getMessage());
        }
    }

    private Map<String, Object> buildRequest(String text) {
        Map<String, Object> actionItem = Map.of(
                "type", "OBJECT",
                "properties", Map.of(
                        "action", Map.of("type", "STRING", "enum", List.of("BLOCK", "UNBLOCK", "WHITELIST")),
                        "ipAddress", Map.of("type", "STRING"),
                        "chain", Map.of("type", "STRING", "enum", List.of("ALL", "INPUT", "OUTPUT", "FORWARD")),
                        "note", Map.of("type", "STRING")),
                "required", List.of("action", "ipAddress"));

        Map<String, Object> schema = Map.of(
                "type", "OBJECT",
                "properties", Map.of("actions", Map.of("type", "ARRAY", "items", actionItem)),
                "required", List.of("actions"));

        return Map.of(
                "system_instruction", Map.of("parts", List.of(Map.of("text", SYSTEM_PROMPT))),
                "contents", List.of(Map.of("role", "user", "parts", List.of(Map.of("text", text)))),
                "generationConfig", Map.of(
                        "responseMimeType", "application/json",
                        "responseSchema", schema,
                        "temperature", 0));
    }

    private List<RawAction> parse(String response) {
        try {
            JsonNode root = objectMapper.readTree(response);
            JsonNode candidates = root.path("candidates");
            if (!candidates.isArray() || candidates.isEmpty()) {
                return List.of();
            }
            JsonNode parts = candidates.get(0).path("content").path("parts");
            if (!parts.isArray() || parts.isEmpty()) {
                return List.of();
            }
            String json = parts.get(0).path("text").asText("");
            if (json.isBlank()) {
                return List.of();
            }
            JsonNode actions = objectMapper.readTree(json).path("actions");
            List<RawAction> result = new ArrayList<>();
            if (actions.isArray()) {
                for (JsonNode a : actions) {
                    result.add(new RawAction(
                            a.path("action").asText(null),
                            a.path("ipAddress").asText(null),
                            a.hasNonNull("chain") ? a.path("chain").asText() : null,
                            a.hasNonNull("note") ? a.path("note").asText() : null));
                }
            }
            return result;
        } catch (Exception e) {
            log.warn("Failed to parse Gemini response", e);
            throw new IllegalStateException("Could not parse the AI response");
        }
    }

    public record RawAction(String action, String ipAddress, String chain, String note) {
    }
}
