package com.railway.auth_service.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

/**
 * Binds all properties under "app.login" to this typed object.
 *
 * Controls brute force protection for user login.
 * Admin login doesn't need this — admins use Google OAuth (no password).
 */
@Getter
@Setter
@Validated
@Component
@ConfigurationProperties(prefix = "app.login")
public class LoginProperties {

  /**
   * Maximum failed login attempts before account is locked.
   * Default: 5.
   *
   * Why 5 and not 3 (like OTP)?
   * OTP is 6 digits — guessable with enough attempts.
   * Password is complex (8+ chars, mixed case, special chars).
   * 5 wrong attempts is likely a real user mistyping, not an attacker.
   * Locking after 3 would frustrate legitimate users.
   */
  private int maxAttempts = 5;

  /**
   * How long the account stays locked after max attempts (seconds).
   * Default: 1800 (30 minutes).
   *
   * Why 30 minutes?
   * Long enough to make brute force impractical:
   *   5 attempts per 30 min = 10/hour = 240/day
   *   A strong password would take centuries to guess at this rate.
   * Short enough that a real user who forgot their password
   * isn't locked out forever.
   */
  private int lockDurationSeconds = 1800;
}
