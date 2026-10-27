package com.bernadetaratna.auth_service.repository;

import com.bernadetaratna.auth_service.model.entity.UserSessions;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserSessionsRepository extends JpaRepository<UserSessions, String> {

    Optional<UserSessions> findBySessionIdAndUserIdAndIsActiveTrue(String sessionId, String userId);

    Optional<UserSessions> findByUserIdAndIsActiveTrue(String userId);

}
