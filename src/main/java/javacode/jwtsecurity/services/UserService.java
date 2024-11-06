package javacode.jwtsecurity.services;

import javacode.jwtsecurity.dtos.request.SignupRequestDTO;
import javacode.jwtsecurity.dtos.response.RegisterDTO;
import javacode.jwtsecurity.models.ERole;
import javacode.jwtsecurity.models.Role;
import javacode.jwtsecurity.models.User;
import javacode.jwtsecurity.repository.RoleRepository;
import javacode.jwtsecurity.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

@Service
@AllArgsConstructor
public class UserService {
    private PasswordEncoder encoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public RegisterDTO signUp(SignupRequestDTO signUpRequest) {
        if (Boolean.TRUE.equals(userRepository.existsByUsername(signUpRequest.getUsername()))) {
            return new RegisterDTO(HttpStatus.BAD_REQUEST, "Error: username is already taken!");
        }

        User user = new User(signUpRequest.getUsername(), encoder.encode(signUpRequest.getPassword()));
        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();
        Supplier<RuntimeException> supplier = () -> new RuntimeException("Error: Role is not found");

        if (strRoles == null) {
            roles.add(roleRepository.findByName(ERole.ROLE_USER).orElseThrow(supplier));
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "super admin" -> roles.add(roleRepository.findByName(ERole.ROLE_SUPER_ADMIN).orElseThrow(supplier));
                    case "moderator" -> roles.add(roleRepository.findByName(ERole.ROLE_MODERATOR).orElseThrow(supplier));
                    default -> roles.add(roleRepository.findByName(ERole.ROLE_USER).orElseThrow(supplier));
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return new RegisterDTO(HttpStatus.OK, "User registered sucсessfully!");
    }
}
