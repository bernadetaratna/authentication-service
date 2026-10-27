package com.bernadetaratna.auth_service.configuration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler globalExceptionHandler;

    @BeforeEach
    void setUp() {
        globalExceptionHandler = new GlobalExceptionHandler();
    }

    @Test
    void handleResponseStatusException_whenReasonExists_returnsExpectedResponse() {
        ResponseStatusException exception = new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "User not found"
        );

        ResponseEntity<Map<String, Object>> response =
                globalExceptionHandler.handleResponseStatusException(exception);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());

        Map<String, Object> body = response.getBody();

        assertEquals(404, body.get("status"));
        assertEquals("Not Found", body.get("error"));
        assertEquals("User not found", body.get("message"));
    }

    @Test
    void handleResponseStatusException_whenReasonIsNull_usesDefaultReasonPhrase() {
        ResponseStatusException exception = new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR
        );

        ResponseEntity<Map<String, Object>> response =
                globalExceptionHandler.handleResponseStatusException(exception);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());

        Map<String, Object> body = response.getBody();

        assertEquals(500, body.get("status"));
        assertEquals("Internal Server Error", body.get("error"));
        assertEquals("Internal Server Error", body.get("message"));
    }

    @Test
    void handleResponseStatusException_whenUnauthorized_returnsUnauthorizedResponse() {
        ResponseStatusException exception = new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Invalid credentials"
        );

        ResponseEntity<Map<String, Object>> response =
                globalExceptionHandler.handleResponseStatusException(exception);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());

        Map<String, Object> body = response.getBody();

        assertEquals(401, body.get("status"));
        assertEquals("Unauthorized", body.get("error"));
        assertEquals("Invalid credentials", body.get("message"));
    }

    @Test
    void handleResponseStatusException_whenConflict_returnsConflictResponse() {
        ResponseStatusException exception = new ResponseStatusException(
                HttpStatus.CONFLICT,
                "Email already exists"
        );

        ResponseEntity<Map<String, Object>> response =
                globalExceptionHandler.handleResponseStatusException(exception);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());

        Map<String, Object> body = response.getBody();

        assertEquals(409, body.get("status"));
        assertEquals("Conflict", body.get("error"));
        assertEquals("Email already exists", body.get("message"));
    }

}