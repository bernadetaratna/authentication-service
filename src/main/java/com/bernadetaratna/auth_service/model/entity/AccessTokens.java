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
@Table(name = "access_tokens")
public class AccessTokens {

    @Id
    @Column(name = "access_token_id", nullable = false)
    private String accessTokenId;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "jti", nullable = false)
    private String jti;

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
