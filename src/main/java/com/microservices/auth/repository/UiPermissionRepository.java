package com.microservices.auth.repository;

import com.microservices.auth.entity.UiPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author nikhil
 * 10/08/25
 */
@Repository
public interface UiPermissionRepository extends JpaRepository<UiPermission, Long> {
   Optional<UiPermission> findByRole(String role);
}
