package com.adaptivesecurity.api.controller;

import com.adaptivesecurity.api.dto.AnalyticsOverview;
import com.adaptivesecurity.api.service.AnalyticsService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/analytics")
@RequiredArgsConstructor
public class AnalyticsController {

    private final AnalyticsService analyticsService;

    @GetMapping("/overview")
    public AnalyticsOverview overview(@RequestParam(defaultValue = "14") int days) {
        return analyticsService.overview(days);
    }
}
