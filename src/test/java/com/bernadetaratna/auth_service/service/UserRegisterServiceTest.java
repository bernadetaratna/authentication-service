package com.bernadetaratna.auth_service.service;

import com.bernadetaratna.auth_service.model.entity.Roles;
import com.bernadetaratna.auth_service.model.entity.UserRoles;
import com.bernadetaratna.auth_service.model.entity.Users;
import com.bernadetaratna.auth_service.model.request.UserRegisterRequest;
import com.bernadetaratna.auth_service.model.response.UserRegisterResponse;
import com.bernadetaratna.auth_service.repository.RolesRepository;
import com.bernadetaratna.auth_service.repository.UserRolesRepository;
import com.bernadetaratna.auth_service.repository.UsersRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static com.bernadetaratna.auth_service.util.Constants.USER_ROLE;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserRegisterServiceTest {

    @Mock
    private UsersRepository usersRepository;

    @Mock
    private RolesRepository rolesRepository;

    @Mock
    private UserRolesRepository userRolesRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserRegisterService userRegisterService;

    private static final String USER_ID = "user-123";
    private static final String ROLE_ID = "role-user-123";
    private static final String EMAIL = "test@example.com";
    private static final String FULL_NAME = "Test User";
    private static final String USERNAME = "testuser";
    private static final String RAW_PASSWORD = "Password123!";
    private static final String HASHED_PASSWORD = "hashed-password";

    private UserRegisterRequest request;

    @BeforeEach
    void setUp() {
        request = new UserRegisterRequest();
        request.setEmail(EMAIL);
        request.setFullName(FULL_NAME);
        request.setUserName(USERNAME);
        request.setPassword(RAW_PASSWORD);
        request.setConfirmPassword(RAW_PASSWORD);
    }

    @Test
    void execute_whenRequestIsValidAndRoleExists_registersUser() {
        when(usersRepository.checkEmailExist(EMAIL))
                .thenReturn(Optional.empty());
        when(usersRepository.checkUserNameExist(USERNAME))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(RAW_PASSWORD))
                .thenReturn(HASHED_PASSWORD);

        when(usersRepository.save(any(Users.class)))
                .thenAnswer(invocation -> {
                    Users savedUser = invocation.getArgument(0);
                    savedUser.setUserId(USER_ID);
                    return savedUser;
                });

        when(rolesRepository.getRoleIdByRoleName(USER_ROLE))
                .thenReturn(Optional.of(ROLE_ID));

        UserRegisterResponse response = userRegisterService.execute(request);

        assertNotNull(response);
        assertEquals(USER_ID, response.getUserId());
        assertEquals(EMAIL, response.getEmail());
        assertEquals(FULL_NAME, response.getFullName());
        assertEquals(USERNAME, response.getUserName());

        verify(usersRepository).save(any(Users.class));
        verify(userRolesRepository).save(any(UserRoles.class));
        verify(rolesRepository, never()).save(any(Roles.class));
    }

    @Test
    void execute_whenRequestIsValidAndRoleDoesNotExist_createsRoleAndRegistersUser() {
        when(usersRepository.checkEmailExist(EMAIL))
                .thenReturn(Optional.empty());
        when(usersRepository.checkUserNameExist(USERNAME))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(RAW_PASSWORD))
                .thenReturn(HASHED_PASSWORD);

        when(usersRepository.save(any(Users.class)))
                .thenAnswer(invocation -> {
                    Users savedUser = invocation.getArgument(0);
                    savedUser.setUserId(USER_ID);
                    return savedUser;
                });

        when(rolesRepository.getRoleIdByRoleName(USER_ROLE))
                .thenReturn(Optional.empty());

        when(rolesRepository.save(any(Roles.class)))
                .thenAnswer(invocation -> {
                    Roles savedRole = invocation.getArgument(0);
                    savedRole.setRoleId(ROLE_ID);
                    return savedRole;
                });

        UserRegisterResponse response = userRegisterService.execute(request);

        assertNotNull(response);
        assertEquals(USER_ID, response.getUserId());

        ArgumentCaptor<Roles> roleCaptor =
                ArgumentCaptor.forClass(Roles.class);

        verify(rolesRepository).save(roleCaptor.capture());

        Roles savedRole = roleCaptor.getValue();
        assertEquals(USER_ROLE, savedRole.getRoleName());
        assertTrue(savedRole.getIsActive());
        assertFalse(savedRole.getIsDeleted());
        assertNotNull(savedRole.getCreatedTime());
        assertNotNull(savedRole.getUpdatedTime());

        verify(userRolesRepository).save(any(UserRoles.class));
    }

    @Test
    void execute_whenRequestIsValid_savesUserWithHashedPassword() {
        when(usersRepository.checkEmailExist(EMAIL))
                .thenReturn(Optional.empty());
        when(usersRepository.checkUserNameExist(USERNAME))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(RAW_PASSWORD))
                .thenReturn(HASHED_PASSWORD);

        when(usersRepository.save(any(Users.class)))
                .thenAnswer(invocation -> {
                    Users savedUser = invocation.getArgument(0);
                    savedUser.setUserId(USER_ID);
                    return savedUser;
                });

        when(rolesRepository.getRoleIdByRoleName(USER_ROLE))
                .thenReturn(Optional.of(ROLE_ID));

        userRegisterService.execute(request);

        ArgumentCaptor<Users> userCaptor =
                ArgumentCaptor.forClass(Users.class);

        verify(usersRepository).save(userCaptor.capture());

        Users savedUser = userCaptor.getValue();

        assertEquals(HASHED_PASSWORD, savedUser.getPassword());
        assertNotEquals(RAW_PASSWORD, savedUser.getPassword());
        assertTrue(savedUser.getIsActive());
        assertFalse(savedUser.getIsDeleted());
        assertNotNull(savedUser.getCreatedTime());
        assertNotNull(savedUser.getUpdatedTime());

        verify(passwordEncoder).encode(RAW_PASSWORD);
    }

    @Test
    void execute_whenEmailAlreadyExists_throwsConflict() {
        when(usersRepository.checkEmailExist(EMAIL))
                .thenReturn(Optional.of(anyString()));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userRegisterService.execute(request)
        );

        assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());

        verify(usersRepository, never()).save(any(Users.class));
        verifyNoInteractions(passwordEncoder);
        verifyNoInteractions(rolesRepository);
        verifyNoInteractions(userRolesRepository);
    }

    @Test
    void execute_whenUsernameAlreadyExists_throwsConflict() {
        when(usersRepository.checkEmailExist(EMAIL))
                .thenReturn(Optional.empty());
        when(usersRepository.checkUserNameExist(USERNAME))
                .thenReturn(Optional.of(anyString()));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userRegisterService.execute(request)
        );

        assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());

        verify(usersRepository, never()).save(any(Users.class));
        verifyNoInteractions(passwordEncoder);
        verifyNoInteractions(rolesRepository);
        verifyNoInteractions(userRolesRepository);
    }

    @Test
    void execute_whenPasswordAndConfirmationDoNotMatch_throwsConflict() {
        when(usersRepository.checkEmailExist(EMAIL))
                .thenReturn(Optional.empty());
        when(usersRepository.checkUserNameExist(USERNAME))
                .thenReturn(Optional.empty());

        request.setConfirmPassword("DifferentPassword123!");

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userRegisterService.execute(request)
        );

        assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());

        verify(usersRepository, never()).save(any(Users.class));
        verifyNoInteractions(passwordEncoder);
        verifyNoInteractions(rolesRepository);
        verifyNoInteractions(userRolesRepository);
    }

    @Test
    void execute_whenPasswordIsCorrectButCaseDiffersFromConfirmation_currentlyAcceptsRequest() {
        when(usersRepository.checkEmailExist(EMAIL))
                .thenReturn(Optional.empty());
        when(usersRepository.checkUserNameExist(USERNAME))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(RAW_PASSWORD))
                .thenReturn(HASHED_PASSWORD);

        when(usersRepository.save(any(Users.class)))
                .thenAnswer(invocation -> {
                    Users savedUser = invocation.getArgument(0);
                    savedUser.setUserId(USER_ID);
                    return savedUser;
                });

        when(rolesRepository.getRoleIdByRoleName(USER_ROLE))
                .thenReturn(Optional.of(ROLE_ID));

        request.setConfirmPassword("pASSWORD123!");

        UserRegisterResponse response = userRegisterService.execute(request);

        assertNotNull(response);
        assertEquals(USER_ID, response.getUserId());
    }

}