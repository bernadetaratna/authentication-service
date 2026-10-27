package com.bernadetaratna.auth_service.repository;

import com.bernadetaratna.auth_service.model.entity.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RolesRepository extends JpaRepository<Roles, String> {

    @Query(value = """
            SELECT role_id FROM roles
            WHERE role_name = :roleName
                AND is_deleted = FALSE
                AND is_active = TRUE
            """, nativeQuery = true)
    Optional<String> getRoleIdByRoleName(@Param("roleName") String roleName);

}
