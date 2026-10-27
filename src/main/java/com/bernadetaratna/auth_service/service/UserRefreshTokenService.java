package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.RefreshTokens;
import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.model.request.UserRefreshTokenRequest;
import com.bernadetaratna.auth_service.model.response.UserRefreshTokenResponse;
import com.bernadetaratna.auth_service.repository.RefreshTokensRepository;
import com.bernadetaratna.auth_service.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;

import static com.bernadetaratna.auth_service.util.Constants.BEARER_TOKEN_TYPE;

@Service
@RequiredArgsConstructor
public class UserRefreshTokenService {

    private final UsersRepository usersRepository;
    private final RefreshTokensRepository refreshTokensRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public UserRefreshTokenResponse execute(UserRefreshTokenRequest request) {
        String hashToken = refreshTokenService.hashToken(request.getRefreshToken());

        RefreshTokens refreshTokens = refreshTokensRepository.getValidRefreshToken(hashToken)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token"));
        Users users = usersRepository.findByUserIdAndIsActiveTrueAndIsDeletedFalse(refreshTokens.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token"));

        String accessToken = jwtService.generateAccessToken(users, refreshTokens.getSessionId());
        Instant expiredAt = Instant.now().plusSeconds(jwtService.getAccessTokenExpirationSeconds());

        return UserRefreshTokenResponse.builder()
                .accessToken(accessToken)
                .tokenType(BEARER_TOKEN_TYPE)
                .expiredTime(expiredAt.toString())
                .expiresIn(Math.toIntExact(jwtService.getAccessTokenExpirationSeconds()))
                .build();
    }

}
