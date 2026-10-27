package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.RefreshTokens;
import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.repository.RefreshTokensRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import static com.bernadetaratna.auth_service.util.CommonUtils.generateRandomUUID;
import static com.bernadetaratna.auth_service.util.Constants.SHA_256;

@Service
public class RefreshTokenService {

    private final RefreshTokensRepository refreshTokensRepository;
    private final long expirationMs;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(
            RefreshTokensRepository refreshTokensRepository,
            @Value("${app.refresh-token.expiration-ms}") long expirationMs
    ) {
        this.refreshTokensRepository = refreshTokensRepository;
        this.expirationMs = expirationMs;
    }

    @Transactional
    public String createRefreshToken(Users user, String sessionId) {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);

        String rawToken = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);

        Instant now = Instant.now();
        Timestamp tsNow = Timestamp.from(now);

        RefreshTokens refreshToken = new RefreshTokens();
        refreshToken.setRefreshTokenId(generateRandomUUID());
        refreshToken.setUserId(user.getUserId());
        refreshToken.setToken(hashToken(rawToken));
        refreshToken.setSessionId(sessionId);
        refreshToken.setExpiredTime(Timestamp.from(now.plusMillis(expirationMs)));
        refreshToken.setRevokedTime(null);
        refreshToken.setCreatedTime(tsNow);
        refreshToken.setUpdatedTime(tsNow);
        refreshTokensRepository.save(refreshToken);

        return rawToken;
    }

    public String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);

            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    public long getExpirationSeconds() {
        return expirationMs / 1000;
    }

}
