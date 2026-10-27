package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.AccessTokens;
import com.bernadetaratna.auth_service.model.entity.RefreshTokens;
import com.bernadetaratna.auth_service.model.request.UserLogoutRequest;
import com.bernadetaratna.auth_service.repository.AccessTokensRepository;
import com.bernadetaratna.auth_service.repository.RefreshTokensRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserLogoutServiceTest {

    @Mock
    private AccessTokensRepository accessTokensRepository;

    @Mock
    private RefreshTokensRepository refreshTokensRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private UserSessionsService userSessionsService;

    @InjectMocks
    private UserLogoutService userLogoutService;

    private static final String USER_ID = "user-123";
    private static final String SESSION_ID = "session-123";
    private static final String JTI = "jti-123";
    private static final String ACCESS_TOKEN = "mock-access-token";
    private static final String RAW_REFRESH_TOKEN = "mock-refresh-token";
    private static final String HASHED_REFRESH_TOKEN = "hashed-refresh-token";

    private UserLogoutRequest request;
    private Claims claims;

    @BeforeEach
    void setUp() {
        request = new UserLogoutRequest();
        request.setRefreshToken(RAW_REFRESH_TOKEN);

        claims = mock(Claims.class);

        lenient().when(claims.getId()).thenReturn(JTI);
        lenient().when(claims.getSubject()).thenReturn(USER_ID);
        lenient().when(claims.get("sessionId", String.class)).thenReturn(SESSION_ID);
    }

    @Test
    void execute_whenTokensAreValid_revokesSession() {
        AccessTokens accessToken = mock(AccessTokens.class);
        RefreshTokens refreshToken = mock(RefreshTokens.class);

        when(jwtService.extractClaims(ACCESS_TOKEN)).thenReturn(claims);

        when(accessTokensRepository.getValidAccessToken(JTI, USER_ID, SESSION_ID))
                .thenReturn(Optional.of(accessToken));

        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);

        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.of(refreshToken));

        when(refreshToken.getUserId()).thenReturn(USER_ID);
        when(refreshToken.getSessionId()).thenReturn(SESSION_ID);

        assertDoesNotThrow(() ->
                userLogoutService.execute(request, ACCESS_TOKEN)
        );

        verify(userSessionsService).revokeSession(SESSION_ID, USER_ID);
    }

    @Test
    void execute_whenAccessTokenIsInvalid_throwsUnauthorized() {
        when(jwtService.extractClaims(ACCESS_TOKEN))
                .thenThrow(new JwtException("Invalid token"));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLogoutService.execute(request, ACCESS_TOKEN)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verifyNoInteractions(accessTokensRepository);
        verifyNoInteractions(refreshTokensRepository);
        verifyNoInteractions(refreshTokenService);
        verifyNoInteractions(userSessionsService);
    }

    @Test
    void execute_whenAccessTokenExtractionThrowsIllegalArgumentException_throwsUnauthorized() {
        when(jwtService.extractClaims(ACCESS_TOKEN))
                .thenThrow(new IllegalArgumentException("Malformed token"));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLogoutService.execute(request, ACCESS_TOKEN)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verifyNoInteractions(accessTokensRepository);
        verifyNoInteractions(refreshTokensRepository);
        verifyNoInteractions(userSessionsService);
    }

    @Test
    void execute_whenSessionIdIsBlank_throwsUnauthorized() {
        when(jwtService.extractClaims(ACCESS_TOKEN)).thenReturn(claims);
        when(claims.get("sessionId", String.class)).thenReturn(" ");

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLogoutService.execute(request, ACCESS_TOKEN)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verifyNoInteractions(accessTokensRepository);
        verifyNoInteractions(refreshTokensRepository);
        verifyNoInteractions(refreshTokenService);
        verifyNoInteractions(userSessionsService);
    }

    @Test
    void execute_whenAccessTokenIsNotValidInDatabase_throwsUnauthorized() {
        when(jwtService.extractClaims(ACCESS_TOKEN)).thenReturn(claims);

        when(accessTokensRepository.getValidAccessToken(JTI, USER_ID, SESSION_ID))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLogoutService.execute(request, ACCESS_TOKEN)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verifyNoInteractions(refreshTokenService);
        verifyNoInteractions(refreshTokensRepository);
        verifyNoInteractions(userSessionsService);
    }

    @Test
    void execute_whenRefreshTokenDoesNotExist_throwsUnauthorized() {
        AccessTokens accessToken = mock(AccessTokens.class);

        when(jwtService.extractClaims(ACCESS_TOKEN)).thenReturn(claims);
        when(accessTokensRepository.getValidAccessToken(JTI, USER_ID, SESSION_ID))
                .thenReturn(Optional.of(accessToken));
        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);
        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLogoutService.execute(request, ACCESS_TOKEN)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(userSessionsService, never()).revokeSession(anyString(), anyString());
    }

    @Test
    void execute_whenRefreshTokenBelongsToDifferentUser_throwsUnauthorized() {
        AccessTokens accessToken = mock(AccessTokens.class);
        RefreshTokens refreshToken = mock(RefreshTokens.class);

        when(jwtService.extractClaims(ACCESS_TOKEN)).thenReturn(claims);
        when(accessTokensRepository.getValidAccessToken(JTI, USER_ID, SESSION_ID))
                .thenReturn(Optional.of(accessToken));
        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);
        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.of(refreshToken));
        when(refreshToken.getUserId()).thenReturn("another-user");
        lenient().when(refreshToken.getSessionId()).thenReturn(SESSION_ID);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLogoutService.execute(request, ACCESS_TOKEN)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(userSessionsService, never()).revokeSession(anyString(), anyString());
    }

    @Test
    void execute_whenRefreshTokenBelongsToDifferentSession_throwsUnauthorized() {
        AccessTokens accessToken = mock(AccessTokens.class);
        RefreshTokens refreshToken = mock(RefreshTokens.class);

        when(jwtService.extractClaims(ACCESS_TOKEN)).thenReturn(claims);
        when(accessTokensRepository.getValidAccessToken(JTI, USER_ID, SESSION_ID))
                .thenReturn(Optional.of(accessToken));
        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);
        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.of(refreshToken));
        when(refreshToken.getUserId()).thenReturn(USER_ID);
        when(refreshToken.getSessionId()).thenReturn("another-session");

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLogoutService.execute(request, ACCESS_TOKEN)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(userSessionsService, never()).revokeSession(anyString(), anyString());
    }

}