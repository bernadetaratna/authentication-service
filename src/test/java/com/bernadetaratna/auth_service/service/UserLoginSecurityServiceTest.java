package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.UserLoginSecurity;
import com.bernadetaratna.auth_service.repository.UserLoginSecurityRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserLoginSecurityServiceTest {

    @Mock
    private UserLoginSecurityRepository userLoginSecurityRepository;

    @InjectMocks
    private UserLoginSecurityService userLoginSecurityService;

    private static final String USER_ID = "user-123";
    private static final String DEVICE_ID = "device-123";

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long WINDOW_MINUTES = 15;
    private static final long LOCK_MINUTES = 15;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(
                userLoginSecurityService,
                "maxFailedAttempts",
                MAX_FAILED_ATTEMPTS
        );
        ReflectionTestUtils.setField(
                userLoginSecurityService,
                "windowMinutes",
                WINDOW_MINUTES
        );
        ReflectionTestUtils.setField(
                userLoginSecurityService,
                "lockMinutes",
                LOCK_MINUTES
        );
    }

    @Test
    void checkLocked_whenSecurityRecordDoesNotExist_doesNothing() {
        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.empty());

        assertDoesNotThrow(() ->
                userLoginSecurityService.checkLocked(USER_ID, DEVICE_ID)
        );

        verify(userLoginSecurityRepository, never()).save(any());
    }

    @Test
    void checkLocked_whenUserIsNotLocked_doesNothing() {
        UserLoginSecurity security = createSecurity(
                2,
                Instant.now().minus(5, ChronoUnit.MINUTES),
                null
        );

        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.of(security));

        assertDoesNotThrow(() ->
                userLoginSecurityService.checkLocked(USER_ID, DEVICE_ID)
        );

        verify(userLoginSecurityRepository, never()).save(any());
    }

    @Test
    void checkLocked_whenLockIsStillActive_throwsTooManyRequests() {
        UserLoginSecurity security = createSecurity(
                5,
                Instant.now(),
                Instant.now().plus(10, ChronoUnit.MINUTES)
        );

        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.of(security));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLoginSecurityService.checkLocked(USER_ID, DEVICE_ID)
        );

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, exception.getStatusCode());
        verify(userLoginSecurityRepository, never()).save(any());
    }

    @Test
    void checkLocked_whenLockHasExpired_resetsSecurityState() {
        UserLoginSecurity security = createSecurity(
                5,
                Instant.now().minus(20, ChronoUnit.MINUTES),
                Instant.now().minus(1, ChronoUnit.MINUTES)
        );

        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.of(security));

        userLoginSecurityService.checkLocked(USER_ID, DEVICE_ID);

        assertEquals(0, security.getFailedAttempts());
        assertNull(security.getStartedTime());
        assertNull(security.getLockedUntil());
        assertNotNull(security.getUpdatedTime());

        verify(userLoginSecurityRepository).save(security);
    }

    @Test
    void updateFailedAttempts_whenRecordDoesNotExist_createsNewRecord() {
        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.empty());

        userLoginSecurityService.updateFailedAttempts(USER_ID, DEVICE_ID);

        ArgumentCaptor<UserLoginSecurity> captor =
                ArgumentCaptor.forClass(UserLoginSecurity.class);

        verify(userLoginSecurityRepository).save(captor.capture());

        UserLoginSecurity saved = captor.getValue();

        assertNotNull(saved.getUserLoginId());
        assertEquals(USER_ID, saved.getUserId());
        assertEquals(DEVICE_ID, saved.getDeviceId());
        assertEquals(1, saved.getFailedAttempts());
        assertNotNull(saved.getStartedTime());
        assertNotNull(saved.getCreatedTime());
        assertNotNull(saved.getUpdatedTime());
        assertNull(saved.getLockedUntil());
    }

    @Test
    void updateFailedAttempts_whenRecordExists_incrementsFailedAttempts() {
        UserLoginSecurity security = createSecurity(
                2,
                Instant.now().minus(5, ChronoUnit.MINUTES),
                null
        );

        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.of(security));

        userLoginSecurityService.updateFailedAttempts(USER_ID, DEVICE_ID);

        assertEquals(3, security.getFailedAttempts());
        assertNotNull(security.getUpdatedTime());

        verify(userLoginSecurityRepository).save(security);
    }

    @Test
    void updateFailedAttempts_whenWindowHasExpired_resetsCounterBeforeIncrementing() {
        UserLoginSecurity security = createSecurity(
                4,
                Instant.now().minus(20, ChronoUnit.MINUTES),
                null
        );

        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.of(security));

        userLoginSecurityService.updateFailedAttempts(USER_ID, DEVICE_ID);

        assertEquals(1, security.getFailedAttempts());
        assertNotNull(security.getStartedTime());

        assertTrue(
                Math.abs(
                        security.getStartedTime().toInstant().toEpochMilli()
                                - Instant.now().toEpochMilli()
                ) < 2_000
        );

        assertNull(security.getLockedUntil());
        verify(userLoginSecurityRepository).save(security);
    }

    @Test
    void updateFailedAttempts_whenMaximumAttemptsReached_locksUser() {
        UserLoginSecurity security = createSecurity(
                4,
                Instant.now().minus(2, ChronoUnit.MINUTES),
                null
        );

        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.of(security));

        Instant beforeCall = Instant.now();

        userLoginSecurityService.updateFailedAttempts(USER_ID, DEVICE_ID);

        Instant afterCall = Instant.now();

        assertEquals(MAX_FAILED_ATTEMPTS, security.getFailedAttempts());
        assertNotNull(security.getLockedUntil());

        Instant expectedEarliestLock = beforeCall.plus(LOCK_MINUTES, ChronoUnit.MINUTES);
        Instant expectedLatestLock = afterCall.plus(LOCK_MINUTES, ChronoUnit.MINUTES);

        assertFalse(security.getLockedUntil().toInstant().isBefore(expectedEarliestLock));
        assertFalse(security.getLockedUntil().toInstant().isAfter(expectedLatestLock));

        verify(userLoginSecurityRepository).save(security);
    }

    @Test
    void resetFailedAttempts_whenRecordExists_resetsSecurityState() {
        UserLoginSecurity security = createSecurity(
                5,
                Instant.now().minus(5, ChronoUnit.MINUTES),
                Instant.now().plus(10, ChronoUnit.MINUTES)
        );

        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.of(security));

        userLoginSecurityService.resetFailedAttempts(USER_ID, DEVICE_ID);

        assertEquals(0, security.getFailedAttempts());
        assertNull(security.getStartedTime());
        assertNull(security.getLockedUntil());
        assertNotNull(security.getUpdatedTime());

        verify(userLoginSecurityRepository).save(security);
    }

    @Test
    void resetFailedAttempts_whenRecordDoesNotExist_doesNothing() {
        when(userLoginSecurityRepository.findByUserIdAndDeviceId(USER_ID, DEVICE_ID))
                .thenReturn(Optional.empty());

        assertDoesNotThrow(() ->
                userLoginSecurityService.resetFailedAttempts(USER_ID, DEVICE_ID)
        );

        verify(userLoginSecurityRepository, never()).save(any());
    }

    private UserLoginSecurity createSecurity(
            int failedAttempts,
            Instant startedTime,
            Instant lockedUntil
    ) {
        Instant now = Instant.now();

        UserLoginSecurity security = UserLoginSecurity.builder()
                .userLoginId("login-security-123")
                .userId(USER_ID)
                .deviceId(DEVICE_ID)
                .failedAttempts(failedAttempts)
                .startedTime(startedTime == null ? null : Timestamp.from(startedTime))
                .createdTime(Timestamp.from(now.minus(30, ChronoUnit.MINUTES)))
                .updatedTime(Timestamp.from(now))
                .build();

        security.setLockedUntil(
                lockedUntil == null ? null : Timestamp.from(lockedUntil)
        );

        return security;
    }

}