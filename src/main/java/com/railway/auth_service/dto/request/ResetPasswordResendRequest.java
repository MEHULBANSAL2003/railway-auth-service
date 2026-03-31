package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPasswordResendRequest {

  @NotBlank(message = "Email, phone, or username is required")
  @Size(max = 255, message = "Identifier must not exceed 255 characters")
  private String identifier;
}
