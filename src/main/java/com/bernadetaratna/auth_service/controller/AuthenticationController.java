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
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api/authentication")
public class AuthenticationController {

    private final UserRegisterService userRegisterService;
    private final UserLoginService userLoginService;
    private final UserRefreshTokenService userRefreshTokenService;
    private final UserLogoutService userLogoutService;

    @PostMapping("/user/register")
    public UserRegisterResponse userRegister(@Valid @RequestBody UserRegisterRequest request) {
        return userRegisterService.execute(request);
    }

    @PostMapping("/user/login")
    public UserLoginResponse userLogin(@Valid @RequestBody UserLoginRequest request,
                                       @RequestHeader("X-Device-Id") String deviceId) {
        if (deviceId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Device ID is required"
            );
        }

        return userLoginService.execute(request, deviceId);
    }

    @PostMapping("/user/refresh/token")
    public UserRefreshTokenResponse userRefreshToken(@Valid @RequestBody UserRefreshTokenRequest request) {
        return userRefreshTokenService.execute(request);
    }

    @PostMapping("/user/logout")
    public void userLogout(@Valid @RequestBody UserLogoutRequest request,
                           @RequestHeader("Authorization") String authorization) {
        if (authorization.isBlank() || !authorization.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bearer access token is required");
        }

        String accessToken = authorization.substring(7);
        userLogoutService.execute(request, accessToken);
    }

}
