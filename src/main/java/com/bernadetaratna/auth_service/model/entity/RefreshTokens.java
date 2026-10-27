package com.bernadetaratna.auth_service.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.sql.Timestamp;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "refresh_tokens")
public class RefreshTokens {

    @Id
    @Column(name = "refresh_token_id", nullable = false)
    private String refreshTokenId;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "token", nullable = false)
    private String token;

    @Column(name = "expired_time", nullable = false)
    private Timestamp expiredTime;

    @Column(name = "revoked_time")
    private Timestamp revokedTime;

    @Column(name = "session_id", nullable = false)
    private String sessionId;

    @Column(name = "created_time", nullable = false)
    private Timestamp createdTime;

    @Column(name = "updated_time", nullable = false)
    private Timestamp updatedTime;

}
