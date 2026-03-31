package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPasswordVerifyRequest {

  @NotBlank(message = "Email, phone, or username is required")
  @Size(max = 255, message = "Identifier must not exceed 255 characters")
  private String identifier;

  @NotBlank(message = "OTP is required")
  @Pattern(
    regexp = "^\\d{6}$",
    message = "OTP must be exactly 6 digits"
  )
  private String otp;

  @NotBlank(message = "New password is required")
  @Pattern(
    regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!?_-]).{8,64}$",
    message = "Password must be 8-64 characters with at least one uppercase, one lowercase, one digit, and one special character"
  )
  private String newPassword;
}
