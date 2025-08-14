package com.microservices.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/health")
@Tag(name = "Health Check", description = "Service health and status endpoints")
public class HealthController {

    @Operation(
        summary = "Health Check",
        description = "Check if the authentication service is running and healthy"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Service is healthy",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    value = """
                    {
                      "status": "UP",
                      "service": "Authentication Service",
                      "timestamp": "2024-01-15T10:30:00",
                      "version": "1.0.0"
                    }
                    """
                )
            )
        )
    })
    @GetMapping
    public ResponseEntity<Map<String, Object>> healthCheck() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "service", "Authentication Service",
            "timestamp", LocalDateTime.now(),
            "version", "1.0.0"
        ));
    }

    @Operation(
        summary = "Service Information",
        description = "Get detailed information about the authentication service"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Service information retrieved successfully",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    value = """
                    {
                      "serviceName": "Authentication Service",
                      "version": "1.0.0",
                      "description": "JWT-based authentication and authorization service",
                      "features": ["User Registration", "User Login", "JWT Token Generation", "Token Validation", "Role-based Access Control"],
                      "endpoints": {
                        "login": "/api/auth/signin",
                        "register": "/api/auth/signup",
                        "validate": "/api/auth/validate",
                        "userInfo": "/api/auth/me"
                      }
                    }
                    """
                )
            )
        )
    })
    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> getServiceInfo() {
        return ResponseEntity.ok(Map.of(
            "serviceName", "Authentication Service",
            "version", "1.0.0",
            "description", "JWT-based authentication and authorization service",
            "features", new String[]{
                "User Registration",
                "User Login", 
                "JWT Token Generation",
                "Token Validation",
                "Role-based Access Control"
            },
            "endpoints", Map.of(
                "login", "/api/auth/signin",
                "register", "/api/auth/signup",
                "validate", "/api/auth/validate",
                "userInfo", "/api/auth/me"
            )
        ));
    }
}
