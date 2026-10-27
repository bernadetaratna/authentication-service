package com.bernadetaratna.auth_service.controller;

import com.bernadetaratna.auth_service.model.request.UserLoginRequest;
import com.bernadetaratna.auth_service.model.request.UserLogoutRequest;
import com.bernadetaratna.auth_service.model.request.UserRefreshTokenRequest;
import com.bernadetaratna.auth_service.model.request.UserRegisterRequest;
import com.bernadetaratna.auth_service.model.response.UserLoginResponse;
import com.bernadetaratna.auth_service.model.response.UserRefreshTokenResponse;
import com.bernadetaratna.auth_service.model.response.UserRegisterResponse;
import com.bernadetaratna.auth_service.service.UserLoginService;
import com.bernadetaratna.auth_service.service.UserLogoutService;
import com.bernadetaratna.auth_service.service.UserRefreshTokenService;
import com.bernadetaratna.auth_service.service.UserRegisterService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationControllerTest {

    @Mock
    private UserRegisterService userRegisterService;

    @Mock
    private UserLoginService userLoginService;

    @Mock
    private UserRefreshTokenService userRefreshTokenService;

    @Mock
    private UserLogoutService userLogoutService;

    @InjectMocks
    private AuthenticationController authenticationController;

    @Test
    void userRegister_whenRequestIsValid_returnsServiceResponse() {
        UserRegisterRequest request = mock(UserRegisterRequest.class);
        UserRegisterResponse expectedResponse = mock(UserRegisterResponse.class);

        when(userRegisterService.execute(request)).thenReturn(expectedResponse);

        UserRegisterResponse actualResponse =
                authenticationController.userRegister(request);

        assertSame(expectedResponse, actualResponse);
        verify(userRegisterService).execute(request);
    }

    @Test
    void userLogin_whenDeviceIdIsValid_returnsServiceResponse() {
        UserLoginRequest request = mock(UserLoginRequest.class);
        UserLoginResponse expectedResponse = mock(UserLoginResponse.class);
        String deviceId = "device-123";

        when(userLoginService.execute(request, deviceId))
                .thenReturn(expectedResponse);

        UserLoginResponse actualResponse =
                authenticationController.userLogin(request, deviceId);

        assertSame(expectedResponse, actualResponse);
        verify(userLoginService).execute(request, deviceId);
    }

    @Test
    void userLogin_whenDeviceIdIsBlank_throwsBadRequest() {
        UserLoginRequest request = mock(UserLoginRequest.class);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> authenticationController.userLogin(request, " ")
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        verifyNoInteractions(userLoginService);
    }

    @Test
    void userRefreshToken_whenRequestIsValid_returnsServiceResponse() {
        UserRefreshTokenRequest request =
                mock(UserRefreshTokenRequest.class);
        UserRefreshTokenResponse expectedResponse =
                mock(UserRefreshTokenResponse.class);

        when(userRefreshTokenService.execute(request))
                .thenReturn(expectedResponse);

        UserRefreshTokenResponse actualResponse =
                authenticationController.userRefreshToken(request);

        assertSame(expectedResponse, actualResponse);
        verify(userRefreshTokenService).execute(request);
    }

    @Test
    void userLogout_whenBearerTokenIsValid_callsServiceWithAccessToken() {
        UserLogoutRequest request = mock(UserLogoutRequest.class);
        String authorization = "Bearer access-token-123";

        authenticationController.userLogout(request, authorization);

        verify(userLogoutService).execute(request, "access-token-123");
    }

    @Test
    void userLogout_whenAuthorizationIsBlank_throwsUnauthorized() {
        UserLogoutRequest request = mock(UserLogoutRequest.class);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> authenticationController.userLogout(request, " ")
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        verifyNoInteractions(userLogoutService);
    }

    @Test
    void userLogout_whenAuthorizationIsNotBearer_throwsUnauthorized() {
        UserLogoutRequest request = mock(UserLogoutRequest.class);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> authenticationController.userLogout(
                        request, "Basic abc123"
                )
        );

        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
        verifyNoInteractions(userLogoutService);
    }

}