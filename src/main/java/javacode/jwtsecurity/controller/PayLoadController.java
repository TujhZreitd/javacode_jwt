package javacode.jwtsecurity.controller;

import javacode.jwtsecurity.dtos.request.LoginRequestDTO;
import javacode.jwtsecurity.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
@AllArgsConstructor
public class PayLoadController {

    private final UserService userService;

    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_MODERATOR') or hasRole('ROLE_SUPER_ADMIN')")
    public String userAccess(Principal principal) {
        return "User Content. Username %s".formatted(principal.getName());
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_SUPER_ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }

    @PostMapping("/user")
    @PreAuthorize("hasRole('ROLE_SUPER_ADMIN')")
    public ResponseEntity<String> unlockUser(@RequestBody LoginRequestDTO loginRequestDTO) {
        userService.unloсkingUser(loginRequestDTO);
        return ResponseEntity.ok("User account unlock");
    }
}
