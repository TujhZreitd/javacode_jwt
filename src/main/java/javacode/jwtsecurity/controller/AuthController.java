package javacode.jwtsecurity.controller;

import jakarta.validation.Valid;
import javacode.jwtsecurity.dtos.request.LoginRequestDTO;
import javacode.jwtsecurity.dtos.request.RefreshTokenDTO;
import javacode.jwtsecurity.dtos.request.SignupRequestDTO;
import javacode.jwtsecurity.dtos.response.JwtRefreshResponseDto;
import javacode.jwtsecurity.dtos.response.JwtResponseDTO;
import javacode.jwtsecurity.dtos.response.MessageResponseDTO;
import javacode.jwtsecurity.dtos.response.RegisterDTO;
import javacode.jwtsecurity.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {

    private final UserService userService;


    @PostMapping("/signup")
    public ResponseEntity<MessageResponseDTO> registerUser(@Valid @RequestBody SignupRequestDTO signUpRequest) {
        RegisterDTO registerDTO = userService.signUp(signUpRequest);
        return ResponseEntity.status(registerDTO.getStatus())
                .body(new MessageResponseDTO(registerDTO.getMessage()));
    }

    @PostMapping("/signin")
    public ResponseEntity<JwtResponseDTO> authenticateUser(@Valid @RequestBody LoginRequestDTO loginRequestDTO) {
        JwtResponseDTO jwtResponseDTO = userService.signIn(loginRequestDTO);
        return ResponseEntity.ok(jwtResponseDTO);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtRefreshResponseDto> refreshToken(@RequestBody RefreshTokenDTO refreshTokenDTO) {
        return ResponseEntity.ok(userService.refreshToken(refreshTokenDTO));
    }
}
