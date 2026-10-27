package com.bernadetaratna.auth_service.repository;

import com.bernadetaratna.auth_service.model.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersRepository extends JpaRepository<Users, String> {

    @Query(value = """
           SELECT user_id FROM users
           WHERE LOWER(email) = LOWER(:email)
                AND is_deleted = FALSE
           """, nativeQuery = true)
    Optional<String> checkEmailExist(@Param("email") String email);

    @Query(value = """
           SELECT user_id FROM users
           WHERE LOWER(user_name) = LOWER(:userName)
                AND is_deleted = FALSE
           """, nativeQuery = true)
    Optional<String> checkUserNameExist(@Param("userName") String userName);

    @Query(value = """
            SELECT * FROM users
            WHERE (
                LOWER(email) = LOWER(:identifier)
                OR LOWER(user_name) = LOWER(:identifier)
            )
            AND is_deleted = FALSE
            AND is_active = TRUE
            """, nativeQuery = true)
    Optional<Users> getActiveUserByIdentifier(@Param("identifier") String identifier);

    Optional<Users> findByUserIdAndIsActiveTrueAndIsDeletedFalse(String userId);
}
