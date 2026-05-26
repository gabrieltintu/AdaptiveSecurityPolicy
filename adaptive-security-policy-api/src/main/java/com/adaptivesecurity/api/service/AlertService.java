package com.adaptivesecurity.api.service;

import com.adaptivesecurity.api.dto.SuspiciousIpInfo;
import com.adaptivesecurity.api.utils.AppConstants;
import com.adaptivesecurity.api.utils.StringUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AlertService {

    private final JavaMailSender mailSender;

    @Value("#{'${security.alerts.recipients}'.split(',')}")
    private String[] recipients;

    @Value("${security.alerts.console-url}")
    private String consoleUrl;

    @Value("${spring.mail.username}")
    private String from;

    @Value("${security.brute-force.warning-threshold}")
    private int warningThreshold;

    @Value("${security.brute-force.block-threshold}")
    private int blockThreshold;

    public void sendWarningAlert(SuspiciousIpInfo info) {
        String subject = StringUtils.formatString(AppConstants.WARNING_EMAIL_SUBJECT, info.getIpAddress());
        String body = StringUtils.formatString(AppConstants.WARNING_EMAIL_BODY,
                info.getIpAddress(), info.getFailedAttempts(), warningThreshold,
                info.getDetectedAt(), blockThreshold, consoleUrl);
        sendEmail(subject, body);
    }

    public void sendBlockAlert(SuspiciousIpInfo info) {
        String subject = StringUtils.formatString(AppConstants.BLOCK_EMAIL_SUBJECT, info.getIpAddress());
        String body = StringUtils.formatString(AppConstants.BLOCK_EMAIL_BODY,
                info.getIpAddress(), info.getFailedAttempts(), blockThreshold,
                info.getDetectedAt(), consoleUrl);
        sendEmail(subject, body);
    }

    private void sendEmail(String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(recipients);
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
    }
}
