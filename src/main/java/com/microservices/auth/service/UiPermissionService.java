package com.microservices.auth.service;

import com.microservices.auth.entity.UiPermission;
import com.microservices.auth.repository.UiPermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UiPermissionService {

    @Autowired
    private UiPermissionRepository repository;

    public List<UiPermission> getAllPermissions() {
        return repository.findAll();
    }

    public Optional<UiPermission> getPermissionById(Long id) {
        return repository.findById(id);
    }

    public Optional<UiPermission> getPermissionByRole(String role) {
        return repository.findByRole(role);
    }

    public UiPermission createPermission(UiPermission permission) {
        return repository.save(permission);
    }

    public UiPermission updatePermission(Long id, UiPermission updatedPermission) {
        return repository.findById(id)
                .map(permission -> {
                    permission.setPermissions(updatedPermission.getPermissions());
                    return repository.save(permission);
                })
                .orElseThrow(() -> new RuntimeException("Permission not found with id " + id));
    }

    public void deletePermission(Long id) {
        repository.deleteById(id);
    }
}
