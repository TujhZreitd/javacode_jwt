package javacode.jwtsecurity.dtos.response;

import lombok.Data;

import java.util.List;

@Data
public class JwtResponseDTO {
    private String accessToken;
    private String refreshToken;
    private String expirationTime;
    private String type = "Bearer";
    private Long id;
    private String username;
    private List<String> roles;

    public JwtResponseDTO(String accessToken, String refreshToken, String expirationTime, Long id, String username, List<String> roles) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expirationTime = expirationTime;
        this.id = id;
        this.username = username;
        this.roles = roles;
    }
}
