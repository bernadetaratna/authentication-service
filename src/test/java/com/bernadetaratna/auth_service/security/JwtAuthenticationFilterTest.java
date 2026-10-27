package com.bernadetaratna.auth_service.security;

import com.bernadetaratna.auth_service.model.entity.AccessTokens;
import com.bernadetaratna.auth_service.model.entity.UserSessions;
import com.bernadetaratna.auth_service.repository.AccessTokensRepository;
import com.bernadetaratna.auth_service.repository.UserSessionsRepository;
import com.bernadetaratna.auth_service.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {

    private JwtService jwtService;
    private AccessTokensRepository accessTokensRepository;
    private UserSessionsRepository userSessionsRepository;
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        jwtService = mock(JwtService.class);
        accessTokensRepository = mock(AccessTokensRepository.class);
        userSessionsRepository = mock(UserSessionsRepository.class);

        jwtAuthenticationFilter = new JwtAuthenticationFilter(
                jwtService,
                accessTokensRepository,
                userSessionsRepository
        );

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        filterChain = mock(FilterChain.class);

        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_whenAuthorizationHeaderIsMissing_doesNotAuthenticate()
            throws Exception {
        when(request.getHeader("Authorization")).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
        verifyNoInteractions(accessTokensRepository);
        verifyNoInteractions(userSessionsRepository);
    }

    @Test
    void doFilterInternal_whenAuthorizationHeaderIsNotBearer_doesNotAuthenticate()
            throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Basic abc123");

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
    }

    @Test
    void doFilterInternal_whenTokenIsValidAndSessionIsActive_authenticatesUser()
            throws Exception {
        String token = "valid.jwt.token";
        String jti = "token-id-123";
        String userId = "user-id-123";
        String sessionId = "session-id-123";

        Claims claims = mock(Claims.class);

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtService.extractClaims(token)).thenReturn(claims);
        when(claims.getId()).thenReturn(jti);
        when(claims.getSubject()).thenReturn(userId);
        when(claims.get("sessionId", String.class)).thenReturn(sessionId);

        AccessTokens accessToken = mock(AccessTokens.class);
        UserSessions session = UserSessions.builder()
                .sessionId(sessionId)
                .userId(userId)
                .isActive(true)
                .build();

        when(accessTokensRepository.getValidAccessToken(jti, userId, sessionId))
                .thenReturn(Optional.of(accessToken));
        when(userSessionsRepository.findBySessionIdAndUserIdAndIsActiveTrue(
                sessionId, userId
        )).thenReturn(Optional.of(session));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(authentication);
        assertEquals(userId, authentication.getPrincipal());
        assertTrue(authentication.isAuthenticated());

        verify(accessTokensRepository)
                .getValidAccessToken(jti, userId, sessionId);
        verify(userSessionsRepository)
                .findBySessionIdAndUserIdAndIsActiveTrue(sessionId, userId);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_whenJwtIsInvalid_doesNotAuthenticate()
            throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Bearer invalid-token");
        when(jwtService.extractClaims("invalid-token"))
                .thenThrow(mock(JwtException.class));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(accessTokensRepository);
        verifyNoInteractions(userSessionsRepository);
    }

    @Test
    void doFilterInternal_whenClaimsAreIncomplete_doesNotAuthenticate()
            throws Exception {
        Claims claims = mock(Claims.class);

        when(request.getHeader("Authorization")).thenReturn("Bearer token");
        when(jwtService.extractClaims("token")).thenReturn(claims);
        when(claims.getId()).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verifyNoInteractions(accessTokensRepository);
        verifyNoInteractions(userSessionsRepository);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_whenAccessTokenIsNotValidInDatabase_doesNotAuthenticate()
            throws Exception {
        mockValidClaims("token-id", "user-id", "session-id");

        when(accessTokensRepository.getValidAccessToken(
                "token-id", "user-id", "session-id"
        )).thenReturn(Optional.empty());

        when(userSessionsRepository.findBySessionIdAndUserIdAndIsActiveTrue(
                "session-id", "user-id"
        )).thenReturn(Optional.of(
                UserSessions.builder()
                        .sessionId("session-id")
                        .userId("user-id")
                        .isActive(true)
                        .build()
        ));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_whenSessionIsNotActive_doesNotAuthenticate()
            throws Exception {
        mockValidClaims("token-id", "user-id", "session-id");

        when(accessTokensRepository.getValidAccessToken(
                "token-id", "user-id", "session-id"
        )).thenReturn(Optional.of(mock(AccessTokens.class)));

        when(userSessionsRepository.findBySessionIdAndUserIdAndIsActiveTrue(
                "session-id", "user-id"
        )).thenReturn(Optional.empty());

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_whenAuthenticationAlreadyExists_doesNotReplaceIt()
            throws Exception {
        var existingAuthentication =
                new org.springframework.security.authentication
                        .UsernamePasswordAuthenticationToken(
                        "existing-user", null, java.util.List.of()
                );

        SecurityContextHolder.getContext()
                .setAuthentication(existingAuthentication);

        mockValidClaims("token-id", "user-id", "session-id");

        when(accessTokensRepository.getValidAccessToken(
                "token-id", "user-id", "session-id"
        )).thenReturn(Optional.of(mock(AccessTokens.class)));

        when(userSessionsRepository.findBySessionIdAndUserIdAndIsActiveTrue(
                "session-id", "user-id"
        )).thenReturn(Optional.of(
                UserSessions.builder()
                        .sessionId("session-id")
                        .userId("user-id")
                        .isActive(true)
                        .build()
        ));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        assertSame(
                existingAuthentication,
                SecurityContextHolder.getContext().getAuthentication()
        );
        verify(filterChain).doFilter(request, response);
    }

    private void mockValidClaims(
            String jti,
            String userId,
            String sessionId
    ) {
        Claims claims = mock(Claims.class);

        when(request.getHeader("Authorization")).thenReturn("Bearer token");
        when(jwtService.extractClaims("token")).thenReturn(claims);
        when(claims.getId()).thenReturn(jti);
        when(claims.getSubject()).thenReturn(userId);
        when(claims.get("sessionId", String.class)).thenReturn(sessionId);
    }

}