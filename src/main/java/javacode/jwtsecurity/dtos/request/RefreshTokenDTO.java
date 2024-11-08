package javacode.jwtsecurity.dtos.request;

import lombok.Data;

@Data
public class RefreshTokenDTO {
    private String username;
    private String password;
    private String token;
}
