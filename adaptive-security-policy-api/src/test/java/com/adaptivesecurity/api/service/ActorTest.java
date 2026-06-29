package com.adaptivesecurity.api.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.adaptivesecurity.api.entity.enums.ActorType;
import org.junit.jupiter.api.Test;

class ActorTest {

    @Test
    void systemActor() {
        Actor a = Actor.system();
        assertThat(a.type()).isEqualTo(ActorType.SYSTEM);
        assertThat(a.username()).isEqualTo("system");
        assertThat(a.userId()).isNull();
    }

    @Test
    void userActorKeepsUsername() {
        Actor a = Actor.user("sub-123", "john");
        assertThat(a.type()).isEqualTo(ActorType.USER);
        assertThat(a.userId()).isEqualTo("sub-123");
        assertThat(a.username()).isEqualTo("john");
    }

    @Test
    void userActorFallsBackToIdWhenUsernameMissing() {
        assertThat(Actor.user("sub-123", null).username()).isEqualTo("sub-123");
        assertThat(Actor.user("sub-123", "   ").username()).isEqualTo("sub-123");
    }
}
