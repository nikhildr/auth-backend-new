package com.microservices.auth.controller;

import com.microservices.auth.entity.Role;
import com.microservices.auth.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/roles")
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Role Management", description = "APIs for creating, updating, retrieving, and deleting roles")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @Operation(
            summary = "Get all roles",
            description = "Retrieves a list of all roles available in the system."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of roles retrieved successfully",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = Role.class)))
    })
    @GetMapping
    public ResponseEntity<List<Role>> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    @Operation(
            summary = "Get role by ID",
            description = "Retrieve a specific role by its unique ID."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role found",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = Role.class))),
            @ApiResponse(responseCode = "404", description = "Role not found")
    })
    @GetMapping("/{id}")
    public ResponseEntity<Role> getRoleById(
            @Parameter(description = "ID of the role to be retrieved") @PathVariable Long id) {
        return roleService.getRoleById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "Create a new role",
            description = "Adds a new role to the system."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role created successfully",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = Role.class))),
            @ApiResponse(responseCode = "400", description = "Invalid request data")
    })
    @PostMapping
    public ResponseEntity<Role> createRole(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Role object to be created",
                    required = true,
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = Role.class),
                            examples = @ExampleObject(value = "{ \"name\": \"ROLE_ADMIN\" }"))
            )
            @RequestBody Role role) {
        return ResponseEntity.ok(roleService.createRole(role));
    }

    @Operation(
            summary = "Update an existing role",
            description = "Updates the details of an existing role by ID."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role updated successfully",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = Role.class))),
            @ApiResponse(responseCode = "404", description = "Role not found")
    })
    @PutMapping("/{id}")
    public ResponseEntity<Role> updateRole(
            @Parameter(description = "ID of the role to update") @PathVariable Long id,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Updated role object",
                    required = true,
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = Role.class),
                            examples = @ExampleObject(value = "{ \"name\": \"ROLE_USER\" }"))
            )
            @RequestBody Role role) {
        return ResponseEntity.ok(roleService.updateRole(id, role));
    }

    @Operation(
            summary = "Delete a role",
            description = "Deletes an existing role by ID."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Role deleted successfully"),
            @ApiResponse(responseCode = "404", description = "Role not found")
    })
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRole(
            @Parameter(description = "ID of the role to delete") @PathVariable Long id) {
        roleService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }
}
