package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.UserSessions;
import com.bernadetaratna.auth_service.repository.AccessTokensRepository;
import com.bernadetaratna.auth_service.repository.RefreshTokensRepository;
import com.bernadetaratna.auth_service.repository.UserSessionsRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserSessionsServiceTest {

    @Mock
    private UserSessionsRepository userSessionsRepository;

    @Mock
    private AccessTokensRepository accessTokensRepository;

    @Mock
    private RefreshTokensRepository refreshTokensRepository;

    @InjectMocks
    private UserSessionsService userSessionsService;

    private static final String USER_ID = "user-123";
    private static final String DEVICE_ID = "device-123";
    private static final String SESSION_ID = "session-123";

    @Test
    void createNewSession_whenNoActiveSessionExists_createsNewSession() {
        when(userSessionsRepository.findByUserIdAndIsActiveTrue(USER_ID))
                .thenReturn(Optional.empty());

        when(userSessionsRepository.save(any(UserSessions.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String sessionId =
                userSessionsService.createNewSession(USER_ID, DEVICE_ID);

        assertNotNull(sessionId);
        assertFalse(sessionId.isBlank());

        ArgumentCaptor<UserSessions> captor =
                ArgumentCaptor.forClass(UserSessions.class);

        verify(userSessionsRepository).save(captor.capture());

        UserSessions savedSession = captor.getValue();

        assertEquals(sessionId, savedSession.getSessionId());
        assertEquals(USER_ID, savedSession.getUserId());
        assertEquals(DEVICE_ID, savedSession.getDeviceId());
        assertTrue(savedSession.getIsActive());
        assertNotNull(savedSession.getCreatedTime());
        assertNotNull(savedSession.getUpdatedTime());
        assertNull(savedSession.getRevokedTime());

        verify(userSessionsRepository, never()).saveAndFlush(any());
        verifyNoInteractions(accessTokensRepository);
        verifyNoInteractions(refreshTokensRepository);
    }

    @Test
    void createNewSession_whenActiveSessionExists_revokesOldSessionAndCreatesNewOne() {
        UserSessions oldSession = createActiveSession(
                SESSION_ID,
                USER_ID,
                "old-device"
        );

        when(userSessionsRepository.findByUserIdAndIsActiveTrue(USER_ID))
                .thenReturn(Optional.of(oldSession));

        when(userSessionsRepository.save(any(UserSessions.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String newSessionId =
                userSessionsService.createNewSession(USER_ID, DEVICE_ID);

        assertNotNull(newSessionId);
        assertNotEquals(SESSION_ID, newSessionId);

        // The old session is revoked.
        assertFalse(oldSession.getIsActive());
        assertNotNull(oldSession.getRevokedTime());
        assertNotNull(oldSession.getUpdatedTime());

        // The new session is saved.
        ArgumentCaptor<UserSessions> captor =
                ArgumentCaptor.forClass(UserSessions.class);

        verify(userSessionsRepository).save(captor.capture());

        UserSessions newSession = captor.getValue();

        assertEquals(newSessionId, newSession.getSessionId());
        assertEquals(USER_ID, newSession.getUserId());
        assertEquals(DEVICE_ID, newSession.getDeviceId());
        assertTrue(newSession.getIsActive());
        assertNull(newSession.getRevokedTime());

        verify(accessTokensRepository).revokeBySessionId(SESSION_ID);
        verify(refreshTokensRepository).revokeBySessionId(SESSION_ID);
        verify(userSessionsRepository).saveAndFlush(oldSession);
    }

    @Test
    void createNewSession_whenActiveSessionExists_revokesOldSessionBeforeSavingNewOne() {
        UserSessions oldSession = createActiveSession(
                SESSION_ID,
                USER_ID,
                "old-device"
        );

        when(userSessionsRepository.findByUserIdAndIsActiveTrue(USER_ID))
                .thenReturn(Optional.of(oldSession));

        when(userSessionsRepository.save(any(UserSessions.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        userSessionsService.createNewSession(USER_ID, DEVICE_ID);

        InOrder order = inOrder(
                accessTokensRepository,
                refreshTokensRepository,
                userSessionsRepository
        );

        order.verify(accessTokensRepository).revokeBySessionId(SESSION_ID);
        order.verify(refreshTokensRepository).revokeBySessionId(SESSION_ID);
        order.verify(userSessionsRepository).saveAndFlush(oldSession);
        order.verify(userSessionsRepository).save(any(UserSessions.class));
    }

    @Test
    void revokeSession_whenActiveSessionExists_revokesSessionAndTokens() {
        UserSessions activeSession = createActiveSession(
                SESSION_ID,
                USER_ID,
                DEVICE_ID
        );

        when(userSessionsRepository.findBySessionIdAndUserIdAndIsActiveTrue(
                SESSION_ID, USER_ID
        )).thenReturn(Optional.of(activeSession));

        userSessionsService.revokeSession(SESSION_ID, USER_ID);

        assertFalse(activeSession.getIsActive());
        assertNotNull(activeSession.getRevokedTime());
        assertNotNull(activeSession.getUpdatedTime());

        verify(accessTokensRepository).revokeBySessionId(SESSION_ID);
        verify(refreshTokensRepository).revokeBySessionId(SESSION_ID);
        verify(userSessionsRepository).saveAndFlush(activeSession);
    }

    @Test
    void revokeSession_whenSessionDoesNotExist_throwsUnauthorized() {
        when(userSessionsRepository.findBySessionIdAndUserIdAndIsActiveTrue(
                SESSION_ID, USER_ID
        )).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userSessionsService.revokeSession(SESSION_ID, USER_ID)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(userSessionsRepository, never()).saveAndFlush(any());
        verifyNoInteractions(accessTokensRepository);
        verifyNoInteractions(refreshTokensRepository);
    }

    @Test
    void revokeSession_whenSessionBelongsToAnotherUser_throwsUnauthorized() {
        String anotherUserId = "another-user";

        when(userSessionsRepository.findBySessionIdAndUserIdAndIsActiveTrue(
                SESSION_ID, anotherUserId
        )).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userSessionsService.revokeSession(
                        SESSION_ID,
                        anotherUserId
                )
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(userSessionsRepository, never()).saveAndFlush(any());
        verifyNoInteractions(accessTokensRepository);
        verifyNoInteractions(refreshTokensRepository);
    }

    private UserSessions createActiveSession(
            String sessionId,
            String userId,
            String deviceId
    ) {
        Timestamp now = Timestamp.from(Instant.now());

        return UserSessions.builder()
                .sessionId(sessionId)
                .userId(userId)
                .deviceId(deviceId)
                .isActive(true)
                .createdTime(now)
                .updatedTime(now)
                .build();
    }

}