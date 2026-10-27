package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.UserSessions;
import com.bernadetaratna.auth_service.repository.AccessTokensRepository;
import com.bernadetaratna.auth_service.repository.RefreshTokensRepository;
import com.bernadetaratna.auth_service.repository.UserSessionsRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

import static com.bernadetaratna.auth_service.util.CommonUtils.generateRandomUUID;

@Service
@RequiredArgsConstructor
public class UserSessionsService {

    private final UserSessionsRepository userSessionsRepository;
    private final AccessTokensRepository accessTokensRepository;
    private final RefreshTokensRepository refreshTokensRepository;

    @Transactional
    public String createNewSession(String userId, String deviceId) {
        Timestamp now = Timestamp.from(Instant.now());

        Optional<UserSessions> activeSessionOpt = userSessionsRepository.findByUserIdAndIsActiveTrue(userId);

        activeSessionOpt.ifPresent(activeSession -> revokeSession(activeSession.getSessionId(), activeSession, now));

        UserSessions newSession = UserSessions.builder()
                .sessionId(generateRandomUUID())
                .userId(userId)
                .deviceId(deviceId)
                .isActive(true)
                .createdTime(now)
                .updatedTime(now)
                .build();

        return userSessionsRepository.save(newSession).getSessionId();
    }

    private void revokeSession(String sessionId, UserSessions activeSession, Timestamp now) {
        accessTokensRepository.revokeBySessionId(sessionId);
        refreshTokensRepository.revokeBySessionId(sessionId);

        activeSession.setIsActive(false);
        activeSession.setRevokedTime(now);
        activeSession.setUpdatedTime(now);
        userSessionsRepository.saveAndFlush(activeSession);
    }

    @Transactional
    public void revokeSession(String sessionId, String userId) {
        Timestamp now = Timestamp.from(Instant.now());

        UserSessions activeSession = userSessionsRepository.findBySessionIdAndUserIdAndIsActiveTrue(sessionId, userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired access token"));

        revokeSession(sessionId, activeSession, now);
    }

}
