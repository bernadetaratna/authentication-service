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
@Table(name = "user_roles")
public class UserRoles {

    @Id
    @Column(name = "user_role_id", nullable = false)
    private String userRoleId;

    @Column(name = "role_id", nullable = false)
    private String roleId;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "created_time", nullable = false)
    private Timestamp createdTime;

    @Column(name = "updated_time", nullable = false)
    private Timestamp updatedTime;

}
