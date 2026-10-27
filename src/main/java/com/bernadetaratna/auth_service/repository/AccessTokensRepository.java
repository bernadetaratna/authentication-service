package com.bernadetaratna.auth_service.repository;

import com.bernadetaratna.auth_service.model.entity.AccessTokens;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccessTokensRepository extends JpaRepository<AccessTokens, String> {

    @Query(value = """
            SELECT * FROM access_tokens
            WHERE jti = :jti
                AND user_id = :userId
                AND session_id = :sessionId
                AND expired_time > CURRENT_TIMESTAMP
                AND revoked_time IS NULL
            FETCH FIRST 1 ROW ONLY
            """, nativeQuery = true)
    Optional<AccessTokens> getValidAccessToken(@Param("jti") String jti,
                                               @Param("userId") String userId,
                                               @Param("sessionId") String sessionId);

    @Modifying
    @Query(value = """
            UPDATE access_tokens
            SET revoked_time = CURRENT_TIMESTAMP,
                updated_time = CURRENT_TIMESTAMP
            WHERE session_id = :sessionId
                AND revoked_time IS NULL
            """, nativeQuery = true)
    void revokeBySessionId(@Param("sessionId") String sessionId);

}
