package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.AccessTokens;
import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.repository.AccessTokensRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Date;

import static com.bernadetaratna.auth_service.util.CommonUtils.generateRandomUUID;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long accessTokenExpirationMs;
    private final AccessTokensRepository accessTokensRepository;

    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.access-token-expiration-ms}") long accessTokenExpirationMs,
            AccessTokensRepository accessTokensRepository
    ) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.accessTokenExpirationMs = accessTokenExpirationMs;
        this.accessTokensRepository = accessTokensRepository;
    }

    @Transactional
    public String generateAccessToken(Users user, String sessionId) {
        Instant now = Instant.now();
        Instant expiredAt = now.plusMillis(accessTokenExpirationMs);
        String jti = generateRandomUUID();
        String userId = user.getUserId();

        AccessTokens accessTokens = AccessTokens.builder()
                .accessTokenId(generateRandomUUID())
                .userId(userId)
                .jti(jti)
                .sessionId(sessionId)
                .expiredTime(Timestamp.from(expiredAt))
                .createdTime(Timestamp.from(now))
                .updatedTime(Timestamp.from(now))
                .build();
        accessTokensRepository.save(accessTokens);

        return Jwts.builder()
                .id(jti)
                .subject(userId)
                .claim("username", user.getUserName())
                .claim("sessionId", sessionId)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiredAt))
                .signWith(signingKey)
                .compact();
    }

    public long getAccessTokenExpirationSeconds() {
        return accessTokenExpirationMs / 1000;
    }

    public Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
