package javacode.jwtsecurity.repository;

import javacode.jwtsecurity.models.ERole;
import javacode.jwtsecurity.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}
