package com.railway.auth_service.dto.request.auth;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RefreshTokenRequest {
  @NotBlank(message = "Refresh token is required")
  private String refreshToken;
}
