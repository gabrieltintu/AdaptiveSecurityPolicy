package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.service.CommandExecutorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    private final CommandExecutorService commandExecutorService;

    @Autowired
    public TestController(CommandExecutorService commandExecutorService) {
        this.commandExecutorService = commandExecutorService;
    }

    @GetMapping("/ping")
    public String ping() {
        return commandExecutorService.execute("echo 'Sistemul comunica perfect cu terminalul Linux!'");
    }

    @GetMapping("/connections")
    public String getRawConnections() {
        return commandExecutorService.execute("ss -tuln");
    }
}