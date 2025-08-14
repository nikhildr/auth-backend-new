package com.microservices.auth.controller;

import com.microservices.auth.entity.BackOfficeUser;
import com.microservices.auth.repository.BackOfficeRepository;
import com.microservices.auth.service.BackOfficeUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequestMapping("/users")
@PreAuthorize("hasRole('ADMIN')")
@RestController
@SecurityRequirement(name = "Bearer Authentication") // applies to all endpoints
public class UserController {

    @Autowired
    BackOfficeRepository userRepository;

    @Autowired
    BackOfficeUserService userService;

    @Operation(
            summary = "Reset User Password",
            description = "Allows admin to reset a user's password by providing username and new password."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset successful"),
            @ApiResponse(responseCode = "400", description = "User not found or password reset failed"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token")
    })
    @PutMapping("/reset-password")
    public ResponseEntity<String> resetPassword(
            @RequestParam String username,
            @RequestParam String newPassword) {
        boolean success = userService.resetPassword(username, newPassword);
        if (success) {
            return ResponseEntity.ok("Password reset successful for user: " + username);
        }
        return ResponseEntity.badRequest().body("User not found or password reset failed.");
    }

    @Operation(
            summary = "Update User",
            description = "Updates an existing user's details by their ID."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User updated successfully"),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token")
    })
    @PutMapping("/{id}")
    public ResponseEntity<BackOfficeUser> updateUser(
            @PathVariable Long id,
            @RequestBody BackOfficeUser updatedUser) {
        return userService.updateUser(id, updatedUser)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "Delete User",
            description = "Deletes a user by their ID."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "User deleted successfully"),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token")
    })
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        return userService.deleteUser(id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    @Operation(
            summary = "Get All Users",
            description = "Retrieves a list of all users in the system."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of users retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token")
    })
    @GetMapping
    public ResponseEntity<List<BackOfficeUser>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }


    @Operation(
            summary = "Get User by ID",
            description = "Retrieve a specific user by their unique ID."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User found",
                    content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token")
    })
    @GetMapping("/{id}")
    public ResponseEntity<BackOfficeUser> getUserById(
            @Parameter(description = "ID of the user to be retrieved") @PathVariable Long id) {
        return userService.getUserById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

}
