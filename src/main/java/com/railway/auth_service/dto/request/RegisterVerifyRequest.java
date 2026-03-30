package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

/**
 * Request body for POST /api/auth/user/register/verify
 *
 * Frontend sends phone (to lookup Redis), OTP (to verify),
 * and password (to hash and store — wasn't stored in Redis).
 */
@Getter
@Setter
public class RegisterVerifyRequest {

  @NotBlank(message = "Phone number is required")
  @Pattern(
    regexp = "^\\d{10}$",
    message = "Phone number must be exactly 10 digits"
  )
  private String phone;

  /**
   * 6-digit OTP entered by user.
   * Why String and not int? OTP "000123" has leading zeros.
   * As int, it becomes 123 — doesn't match stored "000123".
   */
  @NotBlank(message = "OTP is required")
  @Pattern(
    regexp = "^\\d{6}$",
    message = "OTP must be exactly 6 digits"
  )
  private String otp;

  /**
   * Same password rules as RegisterInitiateRequest.
   * Why validate again? Never trust the frontend.
   * User could bypass frontend validation with Postman.
   * Always validate on backend — both times.
   */
  @NotBlank(message = "Password is required")
  @Pattern(
    regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!?_-]).{8,64}$",
    message = "Password must be 8-64 characters with at least one uppercase, one lowercase, one digit, and one special character"
  )
  private String password;
}
