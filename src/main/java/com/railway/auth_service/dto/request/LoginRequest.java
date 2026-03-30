package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * Request body for POST /api/auth/user/login
 *
 * {
 *   "identifier": "mehul@gmail.com",   // or phone or username
 *   "password": "SecurePass@123"
 * }
 *
 * Why no @Pattern on identifier?
 * Identifier can be email, phone, OR username — each has different format.
 * We can't validate format without knowing the type.
 * The service detects the type and validates accordingly.
 * Here we just ensure it's not blank and reasonable length.
 */
@Getter
@Setter
public class LoginRequest {

  @NotBlank(message = "Email, phone, or username is required")
  @Size(max = 255, message = "Identifier must not exceed 255 characters")
  private String identifier;

  @NotBlank(message = "Password is required")
  private String password;
}
