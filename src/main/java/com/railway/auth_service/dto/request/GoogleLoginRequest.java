package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class GoogleLoginRequest {

  @NotBlank(message = "Google ID token is required")
  @Size(max = 4096, message = "Invalid token")
  private String idToken;

}
