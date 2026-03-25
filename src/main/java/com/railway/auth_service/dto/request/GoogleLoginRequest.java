package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class GoogleLoginRequest {

  @NotBlank(message = "Google ID token is required")
  private String idToken;

}
