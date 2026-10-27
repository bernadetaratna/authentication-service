package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.UserLoginSecurity;
import com.bernadetaratna.auth_service.repository.UserLoginSecurityRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static com.bernadetaratna.auth_service.util.CommonUtils.generateRandomUUID;

@Service
@RequiredArgsConstructor
public class UserLoginSecurityService {

    @Value("${app.login-security.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${app.login-security.window-minutes:15}")
    private long windowMinutes;

    @Value("${app.login-security.lock-minutes:15}")
    private long lockMinutes;

    private final UserLoginSecurityRepository userLoginSecurityRepository;

    @Transactional
    public void checkLocked(String userId, String deviceId) {
        UserLoginSecurity userLoginSecurity = userLoginSecurityRepository.findByUserIdAndDeviceId(userId, deviceId)
                .orElse(null);

        if (ObjectUtils.isEmpty(userLoginSecurity) || ObjectUtils.isEmpty(userLoginSecurity.getLockedUntil())) return;

        Instant now = Instant.now();
        Instant lockedUntil = userLoginSecurity.getLockedUntil().toInstant();

        if (lockedUntil.isAfter(now)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many failed login attempts. Please try again later");
        }

        userLoginSecurity.setFailedAttempts(0);
        userLoginSecurity.setStartedTime(null);
        userLoginSecurity.setLockedUntil(null);
        userLoginSecurity.setUpdatedTime(Timestamp.from(now));
        userLoginSecurityRepository.save(userLoginSecurity);
    }

    @Transactional
    public void updateFailedAttempts(String userId, String deviceId) {
        Instant now = Instant.now();
        Timestamp tsNow = Timestamp.from(now);

        UserLoginSecurity userLoginSecurity = userLoginSecurityRepository.findByUserIdAndDeviceId(userId, deviceId)
                .orElseGet(() -> UserLoginSecurity.builder()
                            .userLoginId(generateRandomUUID())
                            .userId(userId)
                            .deviceId(deviceId)
                            .failedAttempts(0)
                            .startedTime(tsNow)
                            .createdTime(tsNow)
                            .updatedTime(tsNow)
                            .build());

        Instant startedTime = userLoginSecurity.getStartedTime().toInstant();

        if (Duration.between(startedTime, now).toMinutes() >= windowMinutes) {
            userLoginSecurity.setFailedAttempts(0);
            startedTime = now;
        }

        userLoginSecurity.setStartedTime(Timestamp.from(startedTime));

        int failedAttempts = userLoginSecurity.getFailedAttempts() + 1;
        userLoginSecurity.setFailedAttempts(failedAttempts);

        if (failedAttempts >= maxFailedAttempts) {
            userLoginSecurity.setLockedUntil(Timestamp.from(now.plus(Duration.ofMinutes(lockMinutes))));
        }

        userLoginSecurity.setUpdatedTime(tsNow);
        userLoginSecurityRepository.save(userLoginSecurity);
    }

    @Transactional
    public void resetFailedAttempts(String userId, String deviceId) {
        userLoginSecurityRepository.findByUserIdAndDeviceId(userId, deviceId)
                .ifPresent(userLogin -> {
                    userLogin.setFailedAttempts(0);
                    userLogin.setStartedTime(null);
                    userLogin.setLockedUntil(null);
                    userLogin.setUpdatedTime(Timestamp.from(Instant.now()));
                    userLoginSecurityRepository.save(userLogin);
                });
    }

}
