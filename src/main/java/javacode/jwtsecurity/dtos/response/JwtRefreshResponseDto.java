package javacode.jwtsecurity.dtos.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtRefreshResponseDto {
    private String accessToken;
    private String refreshToken;
    private String expirationTime;
    private HttpStatus status;
    private String message;
}
