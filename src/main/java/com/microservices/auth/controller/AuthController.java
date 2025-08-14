package com.microservices.auth.controller;

import com.microservices.auth.dto.JwtAuthenticationResponse;
import com.microservices.auth.dto.LoginRequest;
import com.microservices.auth.dto.SignUpRequest;
import com.microservices.auth.entity.BackOfficeUser;
import com.microservices.auth.entity.Role;
import com.microservices.auth.entity.RoleName;
import com.microservices.auth.entity.UiPermission;
import com.microservices.auth.repository.BackOfficeRepository;
import com.microservices.auth.repository.RoleRepository;
import com.microservices.auth.security.JwtTokenProvider;
import com.microservices.auth.service.BackOfficeUserService;
import com.microservices.auth.service.UiPermissionService;
import com.microservices.auth.util.InMemoryTokenBlacklist;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "Authentication and user management endpoints")
@Slf4j
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    BackOfficeRepository userRepository;

    @Autowired
    BackOfficeUserService userService;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtTokenProvider tokenProvider;

    @Autowired
    UiPermissionService uiPermissionService;

    @Autowired
    private  InMemoryTokenBlacklist tokenBlacklist;


    @Operation(summary = "User Login", description = "Authenticate user with username and password to receive JWT token", requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Login credentials", required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = LoginRequest.class), examples = {
            @ExampleObject(name = "Admin Login", summary = "Login as admin user", value = """
                    {
                      "username": "admin",
                      "password": "admin123"
                    }
                    """),
            @ExampleObject(name = "User Login", summary = "Login as regular user", value = """
                    {
                      "username": "user",
                      "password": "user123"
                    }
                    """)
    })))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful", content = @Content(mediaType = "application/json", schema = @Schema(implementation = JwtAuthenticationResponse.class), examples = @ExampleObject(value = """
                    {
                      "accessToken": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20iLCJhdXRob3JpdGllcyI6W3siYXV0aG9yaXR5IjoiUk9MRV9BRE1JTiJ9XSwiaWF0IjoxNzA5NTU2MDAwLCJleHAiOjE3MDk2NDI0MDB9.signature",
                      "tokenType": "Bearer"
                    }
                    """))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject(value = """
                    {
                      "success": false,
                      "message": "Invalid username or password"
                    }
                    """)))
    })
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            System.out.println("DEBUG: Login attempt for username: " + loginRequest.getUsername());

            // Debug: Check if user exists
            Optional<BackOfficeUser> userOptional = userRepository.findByUsername(loginRequest.getUsername());
            if (userOptional.isEmpty()) {
                log.debug("User not found: " + loginRequest.getUsername());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new com.microservices.auth.dto.ApiResponse(false, "Invalid username or password"));
            }

            BackOfficeUser user = userOptional.get();
            log.debug("User found: " + user.getUsername());
            log.debug("Password matches: "
                    + passwordEncoder.matches(loginRequest.getPassword(), user.getPassword()));
            log.debug("password from request :{}", passwordEncoder.encode(loginRequest.getPassword()));
            log.debug("password from db      :{}", user.getPassword());
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword().trim()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = tokenProvider.generateToken(authentication);

            log.debug("Authentication successful for user: " + loginRequest.getUsername());

            Set<Role> roles = user.getRoles();
            AtomicReference<String> perm = new AtomicReference<>("");
            roles.stream().forEach(role -> {
                Optional<UiPermission> permission = uiPermissionService.getPermissionByRole(role.getName().name());

                if (permission.isPresent()) {
                    perm.set(permission.get().getPermissions());
                }
            });
            JwtAuthenticationResponse jwtResponse = new JwtAuthenticationResponse(jwt);
            jwtResponse.setUser(user);
            Set<String> result = Arrays.stream(perm.get().split(","))
                    .map(String::trim) // remove spaces
                    .collect(Collectors.toSet());
            jwtResponse.setUiPermissions(result);
            userService.resetPassword(loginRequest.getUsername(), loginRequest.getPassword().trim());
            return ResponseEntity.ok(jwtResponse);

        } catch (BadCredentialsException e) {
            log.debug(" Bad credentials exception: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new com.microservices.auth.dto.ApiResponse(false, "Invalid username or password"));
        } catch (AuthenticationException e) {
            log.debug(" Authentication exception: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new com.microservices.auth.dto.ApiResponse(false,
                            "Authentication failed: " + e.getMessage()));
        } catch (Exception e) {
            log.debug("Unexpected exception: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new com.microservices.auth.dto.ApiResponse(false, "Internal server error"));
        }
    }

    @Operation(summary = "User Registration", description = "Register a new user with username, email, password and roles", requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "User registration details", required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = SignUpRequest.class), examples = {
            @ExampleObject(name = "Register MERCHANT", summary = "Register new user with Merchant ADMIN role", value = """
                    {
                      "username": "merchant",
                      "email": "merchant@example.com",
                      "password": "password123",
                      "phone":"9872543210",
                      "role": ["merchant"]
                    }
                    """),
            @ExampleObject(name = "Register ADMIN", summary = "Register new user with ADMIN role", value = """
                    {
                      "username": "newadmin",
                      "email": "newadmin@example.com",
                      "password": "password123",
                      "phone":"9876543210",
                      "role": ["admin"]
                    }
                    """),
            @ExampleObject(name = "Register MAKER", summary = "Register new user with Maker role", value = """
                    {
                      "username": "newmaker",
                      "email": "newmaker@example.com",
                      "password": "password123",
                      "phone":"9876543210",
                      "role": ["maker"],
                      "bankCode":"BAK1234567"
                    }
                    """),
            @ExampleObject(name = "Register CHECKER", summary = "Register new user with Checker role", value = """
                    {
                      "username": "newchecker",
                      "email": "newchecker@example.com",
                      "password": "password123",
                      "phone":"9876543210",
                      "role": ["checker"],
                      "bankCode":"BAK1234567"
                    }
                    """),
            @ExampleObject(name = "Register User (Default Role)", summary = "Register user without specifying role (defaults to USER)", value = """
                    {
                      "username": "defaultuser",
                      "email": "defaultuser@example.com",
                      "password": "password123",
                      "phone":"9876543210"
                    }
                    """)
    })))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User registered successfully", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject(value = """
                    {
                      "success": true,
                      "message": "User registered successfully"
                    }
                    """))),
            @ApiResponse(responseCode = "400", description = "Registration failed - username or email already exists", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class), examples = {
                    @ExampleObject(name = "Username Taken", value = """
                            {
                              "success": false,
                              "message": "Username is already taken!"
                            }
                            """),
                    @ExampleObject(name = "Email Taken", value = """
                            {
                              "success": false,
                              "message": "Email Address already in use!"
                            }
                            """)
            }))
    })
    @PostMapping
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        try {
            log.debug("Signup request received for username: {}", signUpRequest.getUsername());
            log.debug("Signup request received for email:{} ", signUpRequest.getEmail());

            if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                log.debug(" Username already exists:{} ", signUpRequest.getUsername());
                return ResponseEntity.badRequest()
                        .body(new com.microservices.auth.dto.ApiResponse(false, "Username is already taken!"));
            }

            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                log.debug("Email already exists: {}", signUpRequest.getEmail());
                return ResponseEntity.badRequest()
                        .body(new com.microservices.auth.dto.ApiResponse(false, "Email Address already in use!"));
            }

            // Creating user's account
            BackOfficeUser user = new BackOfficeUser(signUpRequest.getUsername(),
                    passwordEncoder.encode(signUpRequest.getPassword().trim()),
                    signUpRequest.getEmail(), signUpRequest.getPhone());
            if (signUpRequest.getBankCode() != null) user.setBankCode(signUpRequest.getBankCode());
            if (signUpRequest.getFlexFld1() != null) user.setFlexFld1(signUpRequest.getFlexFld1());
            if (signUpRequest.getFlexFld2() != null) user.setBankCode(signUpRequest.getFlexFld2());

            Set<String> strRoles = signUpRequest.getRole();
            Set<Role> roles = new HashSet<>();

            log.debug("Requested roles: {}", strRoles);

            if (strRoles == null || strRoles.isEmpty()) {
                Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("User Role not found."));
                roles.add(userRole);
                log.debug("Assigned default USER role");
            } else {
                strRoles.forEach(role -> {
                    switch (role.toLowerCase()) {
                        case "admin":
                            Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                                    .orElseThrow(() -> new RuntimeException("Admin Role not found."));
                            roles.add(adminRole);
                            log.debug("Assigned ADMIN role");
                            break;
                        case "maker":
                            Role makerRole = roleRepository.findByName(RoleName.ROLE_MAKER)
                                    .orElseThrow(() -> new RuntimeException("Maker Role not found."));
                            roles.add(makerRole);
                            log.debug("Assigned MAKER role");
                            break;
                        case "checker":
                            Role checkerRole = roleRepository.findByName(RoleName.ROLE_CHECKER)
                                    .orElseThrow(() -> new RuntimeException("Checker Role not found."));
                            roles.add(checkerRole);
                            log.debug("Assigned Cheker role");
                            break;
                        case "merchant":
                            Role superAdmin = roleRepository.findByName(RoleName.ROLE_MERCHANT)
                                    .orElseThrow(() -> new RuntimeException("Super Merchant Role not found."));
                            roles.add(superAdmin);
                            log.debug("Assigned merchant role");
                            break;
                        default:
                            adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                                    .orElseThrow(() -> new RuntimeException("Admin Role not found."));
                            roles.add(adminRole);
                            log.debug("Assigned ADMIN role");
                    }
                });
            }

            user.setRoles(roles);
            BackOfficeUser result = userRepository.save(user);
            //BackOfficeUser result = userService.createUser(user);

            log.debug(" User created successfully: {}", result.getUsername());

            signUpRequest.getRole().forEach(role -> {
                if (role.equalsIgnoreCase("maker") || role.equalsIgnoreCase("checker")) {
                    //send email to created user with user name and password
                }
            });

            return ResponseEntity.ok(new com.microservices.auth.dto.ApiResponse(true, "User registered successfully"));

        } catch (Exception e) {
            log.error("Signup error: {}", e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new com.microservices.auth.dto.ApiResponse(false, "Registration failed: " + e.getMessage()));
        }
    }



    @Operation(
            summary = "User Logout",
            description = "Logs out the user by instructing the client to discard the JWT token",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Logout successful",
                    content = @Content(mediaType = "application/json", examples = @ExampleObject(value = """
                    {
                      "success": true,
                      "message": "You have been logged out successfully"
                    }
                    """))),
    })
    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()) {
            log.debug("User logged out: {}", auth.getName());

            String token = resolveToken(request);
            if (token != null) {
                tokenBlacklist.blacklistToken(token);
                log.debug("Token blacklisted: {}", token);
            }
        } else {
            log.warn("Logout called but no authenticated user found");
        }

        SecurityContextHolder.clearContext();

        return ResponseEntity.ok(
                new com.microservices.auth.dto.ApiResponse(true, "You have been logged out successfully")
        );
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

}
