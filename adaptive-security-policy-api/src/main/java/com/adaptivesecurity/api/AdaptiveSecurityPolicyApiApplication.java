package com.adaptivesecurity.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class AdaptiveSecurityPolicyApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(AdaptiveSecurityPolicyApiApplication.class, args);
    }

}
