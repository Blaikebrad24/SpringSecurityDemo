package com.ProlificCodersio.JwtSecurity.repository;

import com.ProlificCodersio.JwtSecurity.models.ERole;
import com.ProlificCodersio.JwtSecurity.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
