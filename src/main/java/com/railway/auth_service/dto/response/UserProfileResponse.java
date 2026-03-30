package com.railway.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

/**
 * User profile data returned after registration or login.
 *
 * Contains only what the frontend needs to display.
 * Does NOT include:
 *   - passwordHash (never expose)
 *   - status/statusReason (internal, admin-only info)
 *   - device/location info (not relevant to the user)
 *
 * Why separate from User entity?
 * Entity has 20+ fields. Response has ~10.
 * Never expose your entity structure to the frontend.
 * DTO pattern — entity and response evolve independently.
 */
@Getter
@Builder
@AllArgsConstructor
public class UserProfileResponse implements ProfileResponse {

  private Long userId;
  private String username;
  private String fullName;
  private String email;
  private String countryCode;
  private String phone;
  private boolean phoneVerified;
  private boolean emailVerified;
  private String profileImageUrl;
}
