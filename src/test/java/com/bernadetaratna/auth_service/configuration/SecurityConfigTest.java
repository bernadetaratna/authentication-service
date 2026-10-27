package com.bernadetaratna.auth_service.configuration;

import com.bernadetaratna.auth_service.repository.AccessTokensRepository;
import com.bernadetaratna.auth_service.repository.UserSessionsRepository;
import com.bernadetaratna.auth_service.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = SecurityConfigTest.TestController.class)
@AutoConfigureMockMvc()
@Import({
        SecurityConfig.class,
        SecurityConfigTest.TestController.class
})
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityConfig securityConfig;

    @Autowired
    private FilterChainProxy filterChainProxy;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private AccessTokensRepository accessTokensRepository;

    @MockitoBean
    private UserSessionsRepository userSessionsRepository;

    @RestController
    static class TestController {

        @GetMapping("/api/authentication/user/register")
        String register() {
            return "register";
        }

        @GetMapping("/api/authentication/user/login")
        String login() {
            return "login";
        }

        @GetMapping("/api/authentication/user/refresh/token")
        String refreshToken() {
            return "refresh";
        }

        @GetMapping("/api/authentication/user/logout")
        String logout() {
            return "logout";
        }

        @GetMapping("/api/private")
        String privateEndpoint() {
            return "private";
        }
    }

    @Test
    void passwordEncoder_returnsBCryptPasswordEncoder() {
        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

        assertNotNull(passwordEncoder);
        assertTrue(passwordEncoder.matches(
                "my-password",
                passwordEncoder.encode("my-password")
        ));
    }

    @Test
    void passwordEncoder_encodesSamePasswordDifferently() {
        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

        String firstHash = passwordEncoder.encode("my-password");
        String secondHash = passwordEncoder.encode("my-password");

        assertNotEquals(firstHash, secondHash);
        assertTrue(passwordEncoder.matches("my-password", firstHash));
        assertTrue(passwordEncoder.matches("my-password", secondHash));
    }

    @Test
    void registerEndpoint_isPublic() throws Exception {
        mockMvc.perform(get("/api/authentication/user/register"))
                .andExpect(status().isOk());
    }

    @Test
    void loginEndpoint_isPublic() throws Exception {
        mockMvc.perform(get("/api/authentication/user/login"))
                .andExpect(status().isOk());
    }

    @Test
    void refreshTokenEndpoint_isPublic() throws Exception {
        mockMvc.perform(get("/api/authentication/user/refresh/token"))
                .andExpect(status().isOk());
    }

    @Test
    void logoutEndpoint_requiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/authentication/user/logout"))
                .andExpect(status().isForbidden());
    }

    @Test
    void otherEndpoints_requireAuthentication() throws Exception {
        mockMvc.perform(get("/api/private"))
                .andExpect(status().isForbidden());
    }

    @Test
    void securityFilterChain_isRegistered() {
        assertFalse(filterChainProxy.getFilterChains().isEmpty());

        boolean hasAuthorizationFilter =
                filterChainProxy.getFilterChains().stream()
                        .flatMap(chain -> chain.getFilters().stream())
                        .anyMatch(
                                org.springframework.security.web.access.intercept
                                        .AuthorizationFilter.class::isInstance
                        );

        assertTrue(hasAuthorizationFilter,
                "No AuthorizationFilter found in the active security filter chains");
    }

}