package com.railway.auth_service.dto.request.user;


import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LogoutCurrentDeviceRequest {

  @NotBlank(message = "Refresh token is required")
  String refreshToken;
}
