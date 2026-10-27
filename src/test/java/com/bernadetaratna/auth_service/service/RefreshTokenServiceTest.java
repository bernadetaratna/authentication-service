package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.RefreshTokens;
import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.repository.RefreshTokensRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    private static final String USER_ID = "user-123";
    private static final String SESSION_ID = "session-123";
    private static final long EXPIRATION_MS = 604_800_000L;

    @Mock
    private RefreshTokensRepository refreshTokensRepository;

    @Mock
    private Users user;

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(
                refreshTokensRepository,
                EXPIRATION_MS
        );

        lenient().when(user.getUserId()).thenReturn(USER_ID);
    }

    @Test
    void createRefreshToken_whenUserIsValid_returnsRandomToken() {
        String rawToken =
                refreshTokenService.createRefreshToken(user, SESSION_ID);

        assertNotNull(rawToken);
        assertFalse(rawToken.isBlank());

        // 32 random bytes encoded as unpadded Base64 URL-safe text.
        assertEquals(43, rawToken.length());
        assertTrue(rawToken.matches("[A-Za-z0-9_-]+"));

        byte[] decodedToken = Base64.getUrlDecoder().decode(rawToken);
        assertEquals(32, decodedToken.length);

        verify(refreshTokensRepository).save(any(RefreshTokens.class));
    }

    @Test
    void createRefreshToken_whenUserIsValid_savesHashedToken() {
        String rawToken =
                refreshTokenService.createRefreshToken(user, SESSION_ID);

        ArgumentCaptor<RefreshTokens> captor =
                ArgumentCaptor.forClass(RefreshTokens.class);

        verify(refreshTokensRepository).save(captor.capture());

        RefreshTokens savedToken = captor.getValue();

        assertNotNull(savedToken.getRefreshTokenId());
        assertEquals(USER_ID, savedToken.getUserId());
        assertEquals(SESSION_ID, savedToken.getSessionId());

        assertEquals(
                refreshTokenService.hashToken(rawToken),
                savedToken.getToken()
        );

        assertNotEquals(rawToken, savedToken.getToken());
        assertEquals(64, savedToken.getToken().length());
        assertTrue(savedToken.getToken().matches("[0-9a-f]{64}"));
    }

    @Test
    void createRefreshToken_whenUserIsValid_setsExpirationAndTimestamps() {
        Instant beforeCreation = Instant.now();

        refreshTokenService.createRefreshToken(user, SESSION_ID);

        Instant afterCreation = Instant.now();

        ArgumentCaptor<RefreshTokens> captor =
                ArgumentCaptor.forClass(RefreshTokens.class);

        verify(refreshTokensRepository).save(captor.capture());

        RefreshTokens savedToken = captor.getValue();

        Timestamp createdTime = savedToken.getCreatedTime();
        Timestamp updatedTime = savedToken.getUpdatedTime();
        Timestamp expiredTime = savedToken.getExpiredTime();

        assertNotNull(createdTime);
        assertNotNull(updatedTime);
        assertNotNull(expiredTime);

        assertEquals(createdTime, updatedTime);

        assertNull(savedToken.getRevokedTime());

        assertFalse(createdTime.toInstant().isBefore(beforeCreation));
        assertFalse(createdTime.toInstant().isAfter(afterCreation));

        long actualExpirationMs =
                expiredTime.getTime() - createdTime.getTime();

        assertEquals(EXPIRATION_MS, actualExpirationMs);
    }

    @Test
    void createRefreshToken_whenCalledTwice_generatesDifferentTokens() {
        String firstToken =
                refreshTokenService.createRefreshToken(user, SESSION_ID);

        String secondToken =
                refreshTokenService.createRefreshToken(user, SESSION_ID);

        assertNotEquals(firstToken, secondToken);

        verify(refreshTokensRepository, times(2))
                .save(any(RefreshTokens.class));
    }

    @Test
    void hashToken_whenTokenIsValid_returnsSha256HexString() {
        assertEquals(
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                refreshTokenService.hashToken("hello")
        );
    }

    @Test
    void hashToken_whenSameTokenIsProvided_returnsSameHash() {
        String token = "refresh-token-example";

        String firstHash = refreshTokenService.hashToken(token);
        String secondHash = refreshTokenService.hashToken(token);

        assertEquals(firstHash, secondHash);
    }

    @Test
    void getExpirationSeconds_returnsExpirationInSeconds() {
        long expirationSeconds =
                refreshTokenService.getExpirationSeconds();

        assertEquals(604_800L, expirationSeconds);
    }

}