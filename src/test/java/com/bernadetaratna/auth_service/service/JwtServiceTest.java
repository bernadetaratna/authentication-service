package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.AccessTokens;
import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.repository.AccessTokensRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private static final String USER_ID = "user-123";
    private static final String USERNAME = "bernadeta";
    private static final String SESSION_ID = "session-123";
    private static final long EXPIRATION_MS = 900_000L;

    private static final String SECRET = Base64.getEncoder().encodeToString(
            "01234567890123456789012345678901"
                    .getBytes(StandardCharsets.UTF_8)
    );

    private static final String INVALID_SECRET = Base64.getEncoder().encodeToString(
            "abcdefghijklmnopqrstuvwxyz123456"
                    .getBytes(StandardCharsets.UTF_8)
    );

    @Mock
    private AccessTokensRepository accessTokensRepository;

    @Mock
    private Users user;

    private JwtService jwtService;
    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(
                SECRET,
                EXPIRATION_MS,
                accessTokensRepository
        );

        signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET));

        lenient().when(user.getUserId()).thenReturn(USER_ID);
        lenient().when(user.getUserName()).thenReturn(USERNAME);
    }

    @Test
    void generateAccessToken_whenUserIsValid_returnsValidJwt() {
        String token = jwtService.generateAccessToken(user, SESSION_ID);

        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals(USER_ID, claims.getSubject());
        assertEquals(USERNAME, claims.get("username", String.class));
        assertEquals(SESSION_ID, claims.get("sessionId", String.class));
        assertNotNull(claims.getId());
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());
        assertTrue(claims.getExpiration().after(new Date()));

        verify(accessTokensRepository).save(any(AccessTokens.class));
    }

    @Test
    void generateAccessToken_whenUserIsValid_savesAccessTokenToRepository() {
        jwtService.generateAccessToken(user, SESSION_ID);

        ArgumentCaptor<AccessTokens> captor =
                ArgumentCaptor.forClass(AccessTokens.class);

        verify(accessTokensRepository).save(captor.capture());

        AccessTokens savedToken = captor.getValue();

        assertNotNull(savedToken.getAccessTokenId());
        assertEquals(USER_ID, savedToken.getUserId());
        assertNotNull(savedToken.getJti());
        assertEquals(SESSION_ID, savedToken.getSessionId());
        assertNotNull(savedToken.getCreatedTime());
        assertNotNull(savedToken.getUpdatedTime());
        assertNotNull(savedToken.getExpiredTime());

        assertTrue(
                savedToken.getExpiredTime().getTime()
                        > savedToken.getCreatedTime().getTime()
        );
    }

    @Test
    void getAccessTokenExpirationSeconds_returnsExpirationInSeconds() {
        long expirationSeconds =
                jwtService.getAccessTokenExpirationSeconds();

        assertEquals(900L, expirationSeconds);
    }

    @Test
    void extractClaims_whenTokenIsValid_returnsClaims() {
        String token = jwtService.generateAccessToken(user, SESSION_ID);

        Claims claims = jwtService.extractClaims(token);

        assertEquals(USER_ID, claims.getSubject());
        assertEquals(USERNAME, claims.get("username", String.class));
        assertEquals(SESSION_ID, claims.get("sessionId", String.class));
    }

    @Test
    void extractClaims_whenSignatureIsInvalid_throwsJwtException() {
        SecretKey invalidSigningKey =
                Keys.hmacShaKeyFor(Decoders.BASE64.decode(INVALID_SECRET));

        String invalidToken = Jwts.builder()
                .subject(USER_ID)
                .signWith(invalidSigningKey)
                .compact();

        assertThrows(
                JwtException.class,
                () -> jwtService.extractClaims(invalidToken)
        );
    }

    @Test
    void extractClaims_whenTokenIsMalformed_throwsJwtException() {
        assertThrows(
                JwtException.class,
                () -> jwtService.extractClaims("not-a-valid-jwt")
        );
    }

}