package com.bernadetaratna.auth_service.security;

import com.bernadetaratna.auth_service.model.entity.AccessTokens;
import com.bernadetaratna.auth_service.model.entity.UserSessions;
import com.bernadetaratna.auth_service.repository.AccessTokensRepository;
import com.bernadetaratna.auth_service.repository.UserSessionsRepository;
import com.bernadetaratna.auth_service.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final AccessTokensRepository accessTokensRepository;
    private final UserSessionsRepository userSessionsRepository;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            AccessTokensRepository accessTokensRepository,
            UserSessionsRepository userSessionsRepository
    ) {
        this.jwtService = jwtService;
        this.accessTokensRepository = accessTokensRepository;
        this.userSessionsRepository = userSessionsRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.substring(7);

        try {
            Claims claims = jwtService.extractClaims(token);

            String jti = claims.getId();
            String userId = claims.getSubject();
            String sessionId = claims.get("sessionId", String.class);

            if (jti == null || userId == null || sessionId == null) {
                filterChain.doFilter(request, response);
                return;
            }

            Optional<AccessTokens> accessTokenOpt = accessTokensRepository.getValidAccessToken(jti, userId, sessionId);

            Optional<UserSessions> sessionOpt = userSessionsRepository.findBySessionIdAndUserIdAndIsActiveTrue(sessionId, userId);

            if (accessTokenOpt.isEmpty()
                    || sessionOpt.isEmpty()
                    || !userId.equals(sessionOpt.get().getUserId())) {
                filterChain.doFilter(request, response);
                return;
            }

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userId, null, List.of());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (JwtException | IllegalArgumentException e) {
            // JWT invalid, malformed, or expired.
            // No authentication is established.
        }

        filterChain.doFilter(request, response);
    }

}
