package com.microservices.auth.repository;

import com.microservices.auth.entity.BackOfficeUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface BackOfficeRepository extends JpaRepository<BackOfficeUser, Long> {
    Optional<BackOfficeUser> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}
