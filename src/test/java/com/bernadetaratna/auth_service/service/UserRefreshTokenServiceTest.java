package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.RefreshTokens;
import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.model.request.UserRefreshTokenRequest;
import com.bernadetaratna.auth_service.model.response.UserRefreshTokenResponse;
import com.bernadetaratna.auth_service.repository.RefreshTokensRepository;
import com.bernadetaratna.auth_service.repository.UsersRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Optional;

import static com.bernadetaratna.auth_service.util.Constants.BEARER_TOKEN_TYPE;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserRefreshTokenServiceTest {

    @Mock
    private UsersRepository usersRepository;

    @Mock
    private RefreshTokensRepository refreshTokensRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private UserRefreshTokenService userRefreshTokenService;

    private static final String USER_ID = "user-123";
    private static final String SESSION_ID = "session-123";
    private static final String RAW_REFRESH_TOKEN = "raw-refresh-token";
    private static final String HASHED_REFRESH_TOKEN = "hashed-refresh-token";
    private static final String ACCESS_TOKEN = "new-access-token";
    private static final long ACCESS_TOKEN_EXPIRATION_SECONDS = 900L;

    private UserRefreshTokenRequest request;
    private RefreshTokens refreshTokens;
    private Users users;

    @BeforeEach
    void setUp() {
        request = new UserRefreshTokenRequest();
        request.setRefreshToken(RAW_REFRESH_TOKEN);

        refreshTokens = mock(RefreshTokens.class);
        users = mock(Users.class);

        lenient().when(refreshTokens.getUserId()).thenReturn(USER_ID);
        lenient().when(refreshTokens.getSessionId()).thenReturn(SESSION_ID);
    }

    @Test
    void execute_whenRefreshTokenAndUserAreValid_returnsNewAccessToken() {
        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);

        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.of(refreshTokens));

        when(usersRepository.findByUserIdAndIsActiveTrueAndIsDeletedFalse(USER_ID))
                .thenReturn(Optional.of(users));

        when(jwtService.generateAccessToken(users, SESSION_ID))
                .thenReturn(ACCESS_TOKEN);

        when(jwtService.getAccessTokenExpirationSeconds())
                .thenReturn(ACCESS_TOKEN_EXPIRATION_SECONDS);

        Instant beforeCall = Instant.now();

        UserRefreshTokenResponse response =
                userRefreshTokenService.execute(request);

        Instant afterCall = Instant.now();

        assertNotNull(response);
        assertEquals(ACCESS_TOKEN, response.getAccessToken());
        assertEquals(BEARER_TOKEN_TYPE, response.getTokenType());
        assertEquals(900, response.getExpiresIn());

        Instant expiredTime = Instant.parse(response.getExpiredTime());

        assertFalse(
                expiredTime.isBefore(
                        beforeCall.plusSeconds(ACCESS_TOKEN_EXPIRATION_SECONDS)
                )
        );
        assertFalse(
                expiredTime.isAfter(
                        afterCall.plusSeconds(ACCESS_TOKEN_EXPIRATION_SECONDS)
                )
        );

        verify(refreshTokenService).hashToken(RAW_REFRESH_TOKEN);
        verify(refreshTokensRepository)
                .getValidRefreshToken(HASHED_REFRESH_TOKEN);
        verify(usersRepository)
                .findByUserIdAndIsActiveTrueAndIsDeletedFalse(USER_ID);
        verify(jwtService).generateAccessToken(users, SESSION_ID);
    }

    @Test
    void execute_whenRefreshTokenIsInvalid_throwsUnauthorized() {
        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);

        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userRefreshTokenService.execute(request)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verifyNoInteractions(usersRepository);
        verifyNoInteractions(jwtService);
    }

    @Test
    void execute_whenUserDoesNotExist_throwsUnauthorized() {
        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);

        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.of(refreshTokens));

        when(usersRepository.findByUserIdAndIsActiveTrueAndIsDeletedFalse(USER_ID))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userRefreshTokenService.execute(request)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verifyNoInteractions(jwtService);
    }

    @Test
    void execute_whenUserIsInactiveOrDeleted_repositoryReturnsEmptyAndThrowsUnauthorized() {
        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);

        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.of(refreshTokens));

        // Repository query only returns active, non-deleted users.
        when(usersRepository.findByUserIdAndIsActiveTrueAndIsDeletedFalse(USER_ID))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userRefreshTokenService.execute(request)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(jwtService, never())
                .generateAccessToken(any(), anyString());
    }

    @Test
    void execute_whenRefreshTokenIsInvalid_doesNotLookUpUser() {
        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);

        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.empty());

        assertThrows(
                ResponseStatusException.class,
                () -> userRefreshTokenService.execute(request)
        );

        verifyNoInteractions(usersRepository);
        verify(jwtService, never())
                .generateAccessToken(any(), anyString());
        verify(jwtService, never()).getAccessTokenExpirationSeconds();
    }

    @Test
    void execute_whenRefreshIsSuccessful_doesNotCreateAnotherRefreshToken() {
        when(refreshTokenService.hashToken(RAW_REFRESH_TOKEN))
                .thenReturn(HASHED_REFRESH_TOKEN);

        when(refreshTokensRepository.getValidRefreshToken(HASHED_REFRESH_TOKEN))
                .thenReturn(Optional.of(refreshTokens));

        when(usersRepository.findByUserIdAndIsActiveTrueAndIsDeletedFalse(USER_ID))
                .thenReturn(Optional.of(users));

        when(jwtService.generateAccessToken(users, SESSION_ID))
                .thenReturn(ACCESS_TOKEN);

        when(jwtService.getAccessTokenExpirationSeconds())
                .thenReturn(ACCESS_TOKEN_EXPIRATION_SECONDS);

        userRefreshTokenService.execute(request);

        verify(refreshTokenService, never()).createRefreshToken(any(), anyString());
        verify(jwtService).generateAccessToken(users, SESSION_ID);
    }

}