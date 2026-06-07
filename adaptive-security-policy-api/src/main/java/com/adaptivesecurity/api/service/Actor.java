package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.entity.enums.ActorType;

public record Actor(ActorType type, String userId, String username) {

    public static Actor system() {
        return new Actor(ActorType.SYSTEM, null, "system");
    }

    public static Actor user(String userId, String username) {
        return new Actor(ActorType.USER, userId, (username == null || username.isBlank()) ? userId : username);
    }
}
