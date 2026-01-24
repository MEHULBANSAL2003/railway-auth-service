package com.railway.auth_service.dto.request.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.railway.auth_service.enums.LoginMode;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class GoogleAuthRequest {
  @NotBlank(message = "Google token is required")
  @JsonProperty("google_auth_token")
  private String googleAuthToken;
}
