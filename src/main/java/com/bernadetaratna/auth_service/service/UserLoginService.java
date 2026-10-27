package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.UserSessions;
import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.model.request.UserLoginRequest;
import com.bernadetaratna.auth_service.model.response.UserLoginResponse;
import com.bernadetaratna.auth_service.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;

import static com.bernadetaratna.auth_service.util.Constants.BEARER_TOKEN_TYPE;

@Service
@RequiredArgsConstructor
public class UserLoginService {

    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserLoginSecurityService userLoginSecurityService;
    private final UserSessionsService userSessionsService;

    public UserLoginResponse execute(UserLoginRequest request, String deviceId) {
        Users users = validateRequest(request, deviceId);

        userLoginSecurityService.resetFailedAttempts(users.getUserId(), deviceId);

        String sessionId = userSessionsService.createNewSession(users.getUserId(), deviceId);
        String accessToken = jwtService.generateAccessToken(users, sessionId);
        String refreshToken = refreshTokenService.createRefreshToken(users, sessionId);
        Instant expiredAt = Instant.now().plusSeconds(jwtService.getAccessTokenExpirationSeconds());

        UserLoginResponse response = new UserLoginResponse();
        response.setAccessToken(accessToken);
        response.setTokenType(BEARER_TOKEN_TYPE);
        response.setRefreshToken(refreshToken);
        response.setExpiredTime(expiredAt.toString());
        response.setExpiresIn(Math.toIntExact(jwtService.getAccessTokenExpirationSeconds()));
        return response;
    }

    private Users validateRequest(UserLoginRequest request, String deviceId) {
        Users users = usersRepository.getActiveUserByIdentifier(request.getIdentifier())
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email/username or password"));

        userLoginSecurityService.checkLocked(users.getUserId(), deviceId);

        if (!passwordEncoder.matches(request.getPassword(), users.getPassword())) {
            userLoginSecurityService.updateFailedAttempts(users.getUserId(), deviceId);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email/username or password");
        }

        return users;
    }

}
