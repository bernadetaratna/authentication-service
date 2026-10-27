package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.model.request.UserLoginRequest;
import com.bernadetaratna.auth_service.model.response.UserLoginResponse;
import com.bernadetaratna.auth_service.repository.UsersRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Optional;

import static com.bernadetaratna.auth_service.util.Constants.BEARER_TOKEN_TYPE;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserLoginServiceTest {

    @Mock
    private UsersRepository usersRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private UserLoginSecurityService userLoginSecurityService;

    @Mock
    private UserSessionsService userSessionsService;

    @InjectMocks
    private UserLoginService userLoginService;

    private static final String USER_ID = "user-123";
    private static final String USERNAME = "testuser";
    private static final String EMAIL = "test@example.com";
    private static final String RAW_PASSWORD = "Password123!";
    private static final String ENCODED_PASSWORD = "encoded-password";
    private static final String DEVICE_ID = "device-123";
    private static final String SESSION_ID = "session-123";
    private static final String ACCESS_TOKEN = "mock-access-token";
    private static final String REFRESH_TOKEN = "mock-refresh-token";
    private static final long ACCESS_TOKEN_EXPIRATION_SECONDS = 900L;

    private Users users;
    private UserLoginRequest request;

    @BeforeEach
    void setUp() {
        users = Users.builder()
                .userId(USER_ID)
                .userName(USERNAME)
                .email(EMAIL)
                .password(ENCODED_PASSWORD)
                .isActive(true)
                .isDeleted(false)
                .build();

        request = new UserLoginRequest();
        request.setIdentifier(EMAIL);
        request.setPassword(RAW_PASSWORD);
    }

    @Test
    void execute_whenCredentialsAreValid_returnsLoginResponse() {
        when(usersRepository.getActiveUserByIdentifier(EMAIL))
                .thenReturn(Optional.of(users));
        when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD))
                .thenReturn(true);
        when(userSessionsService.createNewSession(USER_ID, DEVICE_ID))
                .thenReturn(SESSION_ID);
        when(jwtService.generateAccessToken(users, SESSION_ID))
                .thenReturn(ACCESS_TOKEN);
        when(refreshTokenService.createRefreshToken(users, SESSION_ID))
                .thenReturn(REFRESH_TOKEN);
        when(jwtService.getAccessTokenExpirationSeconds())
                .thenReturn(ACCESS_TOKEN_EXPIRATION_SECONDS);

        Instant beforeCall = Instant.now();

        UserLoginResponse response =
                userLoginService.execute(request, DEVICE_ID);

        Instant afterCall = Instant.now();

        assertNotNull(response);
        assertEquals(ACCESS_TOKEN, response.getAccessToken());
        assertEquals(BEARER_TOKEN_TYPE, response.getTokenType());
        assertEquals(REFRESH_TOKEN, response.getRefreshToken());
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

        verify(userLoginSecurityService).checkLocked(USER_ID, DEVICE_ID);
        verify(userLoginSecurityService).resetFailedAttempts(USER_ID, DEVICE_ID);
        verify(userSessionsService).createNewSession(USER_ID, DEVICE_ID);
        verify(jwtService).generateAccessToken(users, SESSION_ID);
        verify(refreshTokenService).createRefreshToken(users, SESSION_ID);
    }

    @Test
    void execute_whenUserDoesNotExist_throwsUnauthorized() {
        when(usersRepository.getActiveUserByIdentifier(EMAIL))
                .thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLoginService.execute(request, DEVICE_ID)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verifyNoInteractions(passwordEncoder);
        verifyNoInteractions(userLoginSecurityService);
        verifyNoInteractions(userSessionsService);
        verifyNoInteractions(jwtService);
        verifyNoInteractions(refreshTokenService);
    }

    @Test
    void execute_whenPasswordIsIncorrect_recordsFailedAttemptAndThrowsUnauthorized() {
        when(usersRepository.getActiveUserByIdentifier(EMAIL))
                .thenReturn(Optional.of(users));
        when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD))
                .thenReturn(false);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLoginService.execute(request, DEVICE_ID)
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());

        verify(userLoginSecurityService).checkLocked(USER_ID, DEVICE_ID);
        verify(userLoginSecurityService).updateFailedAttempts(USER_ID, DEVICE_ID);
        verify(userLoginSecurityService, never())
                .resetFailedAttempts(anyString(), anyString());

        verifyNoInteractions(userSessionsService);
        verifyNoInteractions(jwtService);
        verifyNoInteractions(refreshTokenService);
    }

    @Test
    void execute_whenUserIsLocked_throwsTooManyRequests() {
        when(usersRepository.getActiveUserByIdentifier(EMAIL))
                .thenReturn(Optional.of(users));

        doThrow(new ResponseStatusException(
                HttpStatus.TOO_MANY_REQUESTS,
                "Too many failed login attempts"
        )).when(userLoginSecurityService).checkLocked(USER_ID, DEVICE_ID);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userLoginService.execute(request, DEVICE_ID)
        );

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, exception.getStatusCode());

        verifyNoInteractions(passwordEncoder);
        verify(userLoginSecurityService, never())
                .updateFailedAttempts(anyString(), anyString());
        verify(userLoginSecurityService, never())
                .resetFailedAttempts(anyString(), anyString());

        verifyNoInteractions(userSessionsService);
        verifyNoInteractions(jwtService);
        verifyNoInteractions(refreshTokenService);
    }

    @Test
    void execute_whenPasswordIsCorrect_resetsFailedAttemptsBeforeCreatingSession() {
        when(usersRepository.getActiveUserByIdentifier(EMAIL))
                .thenReturn(Optional.of(users));
        when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD))
                .thenReturn(true);
        when(userSessionsService.createNewSession(USER_ID, DEVICE_ID))
                .thenReturn(SESSION_ID);
        when(jwtService.generateAccessToken(users, SESSION_ID))
                .thenReturn(ACCESS_TOKEN);
        when(refreshTokenService.createRefreshToken(users, SESSION_ID))
                .thenReturn(REFRESH_TOKEN);
        when(jwtService.getAccessTokenExpirationSeconds())
                .thenReturn(ACCESS_TOKEN_EXPIRATION_SECONDS);

        userLoginService.execute(request, DEVICE_ID);

        var order = inOrder(userLoginSecurityService, userSessionsService);

        order.verify(userLoginSecurityService)
                .resetFailedAttempts(USER_ID, DEVICE_ID);
        order.verify(userSessionsService)
                .createNewSession(USER_ID, DEVICE_ID);
    }

    @Test
    void execute_whenPasswordIsIncorrect_doesNotCreateSessionOrTokens() {
        when(usersRepository.getActiveUserByIdentifier(EMAIL))
                .thenReturn(Optional.of(users));
        when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD))
                .thenReturn(false);

        assertThrows(
                ResponseStatusException.class,
                () -> userLoginService.execute(request, DEVICE_ID)
        );

        verify(userSessionsService, never())
                .createNewSession(anyString(), anyString());
        verify(jwtService, never())
                .generateAccessToken(any(), anyString());
        verify(refreshTokenService, never())
                .createRefreshToken(any(), anyString());
    }

}