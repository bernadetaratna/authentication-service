package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.AccessTokens;
import com.bernadetaratna.auth_service.model.entity.RefreshTokens;
import com.bernadetaratna.auth_service.model.request.UserLogoutRequest;
import com.bernadetaratna.auth_service.repository.AccessTokensRepository;
import com.bernadetaratna.auth_service.repository.RefreshTokensRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class UserLogoutService {

    private final AccessTokensRepository accessTokensRepository;
    private final RefreshTokensRepository refreshTokensRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserSessionsService userSessionsService;

    public static final String ERR_MSG_INVALID_TOKEN = "Invalid or expired access token";

    @Transactional
    public void execute(UserLogoutRequest request, String accessToken) {
        Claims claims;

        try {
            claims = jwtService.extractClaims(accessToken);
        } catch (JwtException | IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, ERR_MSG_INVALID_TOKEN);
        }

        String jti = claims.getId();
        String userId = claims.getSubject();

        String sessionId = claims.get("sessionId", String.class);
        if (sessionId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, ERR_MSG_INVALID_TOKEN);
        }

        validateToken(request, jti, userId, sessionId);
        userSessionsService.revokeSession(sessionId, userId);
    }

    private void validateToken(UserLogoutRequest request, String jti, String userId, String sessionId) {
        accessTokensRepository.getValidAccessToken(jti, userId, sessionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, ERR_MSG_INVALID_TOKEN));

        String hashToken = refreshTokenService.hashToken(request.getRefreshToken());
        refreshTokensRepository.getValidRefreshToken(hashToken)
                .filter(token -> token.getUserId().equalsIgnoreCase(userId))
                .filter(token -> token.getSessionId().equalsIgnoreCase(sessionId))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, ERR_MSG_INVALID_TOKEN));
    }

}
