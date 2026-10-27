package com.bernadetaratna.auth_service.repository;

import com.bernadetaratna.auth_service.model.entity.RefreshTokens;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokensRepository extends JpaRepository<RefreshTokens, String> {

    @Query(value = """
            SELECT * FROM refresh_tokens
            WHERE token = :refreshToken
                AND expired_time > CURRENT_TIMESTAMP
                AND revoked_time IS NULL
            FETCH FIRST 1 ROW ONLY
            """, nativeQuery = true)
    Optional<RefreshTokens> getValidRefreshToken(@Param("refreshToken") String refreshToken);

    @Modifying
    @Query(value = """
            UPDATE refresh_tokens
            SET revoked_time = CURRENT_TIMESTAMP,
                updated_time = CURRENT_TIMESTAMP
            WHERE session_id = :sessionId
                AND revoked_time IS NULL
            """, nativeQuery = true)
    void revokeBySessionId(@Param("sessionId") String sessionId);

}
