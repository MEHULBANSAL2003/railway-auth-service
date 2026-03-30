package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * Request body for POST /api/auth/user/register/initiate
 *
 * All fields are mandatory for registration.
 * Password is sent here but NOT stored in Redis —
 * it will be sent again at verification step.
 */
@Getter
@Setter
public class RegisterInitiateRequest {

  /**
   * Unique handle like "mehul_123".
   *
   * Rules:
   *   - Must start with a letter (prevents all-digit usernames
   *     which would be confused with phone numbers during login)
   *   - Only letters, numbers, underscores
   *   - 3 to 30 characters
   *
   * Why these specific rules?
   *   Login detection: "@" → email, 10 digits → phone, else → username.
   *   If username could be all digits, "9876543210" is ambiguous —
   *   is it a phone or username? Starting with a letter eliminates this.
   */
  @NotBlank(message = "Username is required")
  @Pattern(
    regexp = "^[a-zA-Z][a-zA-Z0-9_]{2,29}$",
    message = "Username must start with a letter, contain only letters, numbers, and underscores, and be 3-30 characters"
  )
  private String username;

  @NotBlank(message = "Full name is required")
  @Size(max = 200, message = "Full name must not exceed 200 characters")
  private String fullName;

  /**
   * Why @Email AND @NotBlank?
   * @Email alone allows empty string — it validates format only if present.
   * @NotBlank ensures it's not empty. Both needed together.
   */
  @NotBlank(message = "Email is required")
  @Email(message = "Invalid email format")
  private String email;



  /**
   * Exactly 10 digits, no spaces, no dashes.
   * Country code is separate — this is just the number.
   */
  @NotBlank(message = "Phone number is required")
  @Pattern(
    regexp = "^\\d{10}$",
    message = "Phone number must be exactly 10 digits"
  )
  private String phone;

  /**
   * Password complexity rules:
   *   - 8 to 64 characters
   *   - At least one uppercase letter (A-Z)
   *   - At least one lowercase letter (a-z)
   *   - At least one digit (0-9)
   *   - At least one special character (@#$%^&+=!?_-)
   *
   * Why max 64?
   * bcrypt has a 72-byte limit. Beyond that, extra characters are ignored.
   * 64 chars is safe with UTF-8 encoding.
   *
   * Why sent here if not stored in Redis?
   * We validate it here so user gets immediate feedback if password is weak.
   * They don't fill the form → get OTP → enter OTP → then find out password
   * is invalid. Fail fast — validate everything upfront.
   */
  @NotBlank(message = "Password is required")
  @Pattern(
    regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!?_-]).{8,64}$",
    message = "Password must be 8-64 characters with at least one uppercase, one lowercase, one digit, and one special character"
  )
  private String password;
}
