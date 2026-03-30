package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

/**
 * Request body for POST /api/auth/user/register/resend
 * Only phone needed — registration data is already in Redis.
 */
@Getter
@Setter
public class RegisterResendRequest {

  @NotBlank(message = "Phone number is required")
  @Pattern(
    regexp = "^\\d{10}$",
    message = "Phone number must be exactly 10 digits"
  )
  private String phone;
}
