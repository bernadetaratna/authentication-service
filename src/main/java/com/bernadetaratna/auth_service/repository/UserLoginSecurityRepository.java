package com.bernadetaratna.auth_service.repository;

import com.bernadetaratna.auth_service.model.entity.UserLoginSecurity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserLoginSecurityRepository extends JpaRepository<UserLoginSecurity, String> {

    Optional<UserLoginSecurity> findByUserIdAndDeviceId(String userId, String deviceId);

}
