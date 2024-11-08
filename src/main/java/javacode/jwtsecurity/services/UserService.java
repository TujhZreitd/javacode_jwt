package javacode.jwtsecurity.services;

import javacode.jwtsecurity.dtos.request.LoginRequestDTO;
import javacode.jwtsecurity.dtos.request.RefreshTokenDTO;
import javacode.jwtsecurity.dtos.request.SignupRequestDTO;
import javacode.jwtsecurity.dtos.response.JwtRefreshResponseDto;
import javacode.jwtsecurity.dtos.response.JwtResponseDTO;
import javacode.jwtsecurity.dtos.response.RegisterDTO;
import javacode.jwtsecurity.jwt.JwtUtils;
import javacode.jwtsecurity.models.ERole;
import javacode.jwtsecurity.models.Role;
import javacode.jwtsecurity.models.User;
import javacode.jwtsecurity.repository.RoleRepository;
import javacode.jwtsecurity.repository.UserRepository;
import javacode.jwtsecurity.userdetails.UserDetailsImpl;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.function.Supplier;

@Service
@AllArgsConstructor
public class UserService {
    private PasswordEncoder encoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private static final int MAX_FAILED_ATTEMPTS = 5;

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

    public JwtResponseDTO signIn(LoginRequestDTO loginRequestDTO) {
        JwtResponseDTO result = null;
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequestDTO.getUsername(), loginRequestDTO.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);
            String jwtRefresh = jwtUtils.generateRefreshToken(new HashMap<>(), authentication);
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            loginSucceeded(userRepository.findByUsername(loginRequestDTO.getUsername()));
            result = new JwtResponseDTO(jwt, jwtRefresh, "24 hours", userDetails.getId(), userDetails.getUsername(), roles);
        } catch (AuthenticationException e) {
            loginFailed(userRepository.findByUsername(loginRequestDTO.getUsername()));
            throw new RuntimeException(e.getMessage());
        }

        return result;
    }

    public JwtRefreshResponseDto refreshToken(RefreshTokenDTO refreshTokenDTO) {
        String username = jwtUtils.extractUsername(refreshTokenDTO.getToken());
        User user = userRepository.findByUsername(username).orElseThrow();
        JwtRefreshResponseDto result = new JwtRefreshResponseDto();
        if (jwtUtils.validateJwtToken(refreshTokenDTO.getToken(), (UserDetails) user)) {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(refreshTokenDTO.getUsername(), refreshTokenDTO.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);
            result.setStatus(HttpStatus.OK);
            result.setAccessToken(jwt);
            result.setRefreshToken(refreshTokenDTO.getToken());
            result.setExpirationTime("24 hours");
            result.setMessage("Successfully Refreshed Token");
        }
        return result;
    }

    public void unloсkingUser(LoginRequestDTO loginRequestDTO) {
        loginSucceeded(userRepository.findByUsername(loginRequestDTO.getUsername()));
    }



    private void loginFailed(Optional<User> userOptional) {
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            int newFailAttempts = user.getCountFailedAttempts() + 1;
            user.setCountFailedAttempts(newFailAttempts);
            if (newFailAttempts >= MAX_FAILED_ATTEMPTS) {
                user.setAccountLocked(true);
            }
            userRepository.save(user);
        }
    }

    private void loginSucceeded(Optional<User> userOptional) {
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setCountFailedAttempts(0);
            user.setAccountLocked(false);
            userRepository.save(user);
        }
    }
}
