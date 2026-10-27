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
@Table(name = "user_login_security")
public class UserLoginSecurity {

    @Id
    @Column(name = "user_login_id", nullable = false)
    private String userLoginId;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "device_id", nullable = false)
    private String deviceId;

    @Column(name = "failed_attempts", nullable = false)
    private Integer failedAttempts;

    @Column(name = "started_time")
    private Timestamp startedTime;

    @Column(name = "locked_until")
    private Timestamp lockedUntil;

    @Column(name = "created_time", nullable = false)
    private Timestamp createdTime;

    @Column(name = "updated_time", nullable = false)
    private Timestamp updatedTime;

}
