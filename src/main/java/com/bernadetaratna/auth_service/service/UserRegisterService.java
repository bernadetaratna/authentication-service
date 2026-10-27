package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.Roles;
import com.bernadetaratna.auth_service.model.entity.UserRoles;
import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.model.request.UserRegisterRequest;
import com.bernadetaratna.auth_service.model.response.UserRegisterResponse;
import com.bernadetaratna.auth_service.repository.RolesRepository;
import com.bernadetaratna.auth_service.repository.UserRolesRepository;
import com.bernadetaratna.auth_service.repository.UsersRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Instant;

import static com.bernadetaratna.auth_service.util.CommonUtils.generateRandomUUID;
import static com.bernadetaratna.auth_service.util.Constants.USER_ROLE;

@Service
@RequiredArgsConstructor
public class UserRegisterService {

    private final UsersRepository usersRepository;
    private final RolesRepository rolesRepository;
    private final UserRolesRepository userRolesRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserRegisterResponse execute(UserRegisterRequest request) {
        validateRequest(request);
        String hashPassword = passwordEncoder.encode(request.getPassword());
        String userId = insertUser(request, hashPassword);

        return UserRegisterResponse.builder()
                .userId(userId)
                .email(request.getEmail())
                .fullName(request.getFullName())
                .userName(request.getUserName())
                .build();
    }

    private String insertUser(UserRegisterRequest request, String hashPassword) {
        Timestamp now = Timestamp.from(Instant.now());

        Users users = Users.builder()
                .userId(generateRandomUUID())
                .email(request.getEmail())
                .fullName(request.getFullName())
                .userName(request.getUserName())
                .password(hashPassword)
                .isActive(true)
                .isDeleted(false)
                .createdTime(now)
                .updatedTime(now)
                .build();
        String userId = usersRepository.save(users).getUserId();

        String roleId = rolesRepository.getRoleIdByRoleName(USER_ROLE).orElseGet(() -> {
            Roles roles = Roles.builder()
                    .roleId(generateRandomUUID())
                    .roleName(USER_ROLE)
                    .isActive(true)
                    .isDeleted(false)
                    .createdTime(now)
                    .updatedTime(now)
                    .build();
            return rolesRepository.save(roles).getRoleId();
        });

        UserRoles userRoles = UserRoles.builder()
                .userRoleId(generateRandomUUID())
                .userId(userId)
                .roleId(roleId)
                .isActive(true)
                .isDeleted(false)
                .createdTime(now)
                .updatedTime(now)
                .build();
        userRolesRepository.save(userRoles);

        return userId;
    }

    private void validateRequest(UserRegisterRequest request) {
        if (usersRepository.checkEmailExist(request.getEmail()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered, please Log In");
        }

        if (usersRepository.checkUserNameExist(request.getUserName()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already used");
        }

        if (!request.getPassword().equalsIgnoreCase(request.getConfirmPassword())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Confirm Password different with Password");
        }
    }

}
