package com.railway.auth_service.dto.request.admin;


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
