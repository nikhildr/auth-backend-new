package com.microservices.auth.controller;

import com.microservices.auth.entity.UiPermission;
import com.microservices.auth.service.UiPermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/ui-permissions")
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "UI Permissions", description = "Endpoints for managing UI permissions")
public class UiPermissionController {

    @Autowired
    private UiPermissionService service;

    @Operation(
            summary = "Get all UI permissions",
            description = "Retrieves a list of all UI permissions available in the system",
            responses = {
                    @ApiResponse(responseCode = "200", description = "List retrieved successfully",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = UiPermission.class))),
                    @ApiResponse(responseCode = "403", description = "Forbidden - insufficient permissions"),
            }
    )
    @GetMapping
    public ResponseEntity<List<UiPermission>> getAllPermissions() {
        return ResponseEntity.ok(service.getAllPermissions());
    }

    @Operation(
            summary = "Get UI permission by ID",
            description = "Retrieves a single UI permission using its unique ID",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Permission found",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = UiPermission.class))),
                    @ApiResponse(responseCode = "404", description = "Permission not found"),
                    @ApiResponse(responseCode = "403", description = "Forbidden - insufficient permissions")
            }
    )
    @GetMapping("/{id}")
    public ResponseEntity<UiPermission> getPermissionById(
            @Parameter(description = "ID of the permission to retrieve", example = "1")
            @PathVariable Long id) {
        return service.getPermissionById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "Create a new UI permission",
            description = "Adds a new UI permission to the system",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Permission created successfully",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = UiPermission.class))),
                    @ApiResponse(responseCode = "403", description = "Forbidden - insufficient permissions")
            }
    )
    @PostMapping
    public ResponseEntity<UiPermission> createPermission(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "UI permission details",
                    required = true,
                    content = @Content(schema = @Schema(implementation = UiPermission.class))
            )
            @RequestBody UiPermission permission) {
        return ResponseEntity.ok(service.createPermission(permission));
    }

    @Operation(
            summary = "Update an existing UI permission",
            description = "Updates the details of an existing UI permission",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Permission updated successfully",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = UiPermission.class))),
                    @ApiResponse(responseCode = "404", description = "Permission not found"),
                    @ApiResponse(responseCode = "403", description = "Forbidden - insufficient permissions")
            }
    )
    @PutMapping("/{id}")
    public ResponseEntity<UiPermission> updatePermission(
            @Parameter(description = "ID of the permission to update", example = "1")
            @PathVariable Long id,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Updated permission details",
                    required = true,
                    content = @Content(schema = @Schema(implementation = UiPermission.class))
            )
            @RequestBody UiPermission updatedPermission) {
        return ResponseEntity.ok(service.updatePermission(id, updatedPermission));
    }

    @Operation(
            summary = "Delete a UI permission",
            description = "Deletes an existing UI permission by its ID",
            responses = {
                    @ApiResponse(responseCode = "204", description = "Permission deleted successfully"),
                    @ApiResponse(responseCode = "404", description = "Permission not found"),
                    @ApiResponse(responseCode = "403", description = "Forbidden - insufficient permissions")
            }
    )
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePermission(
            @Parameter(description = "ID of the permission to delete", example = "1")
            @PathVariable Long id) {
        service.deletePermission(id);
        return ResponseEntity.noContent().build();
    }
}
