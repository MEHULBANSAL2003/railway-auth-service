package com.railway.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

/**
 * Admin profile data returned after admin login.
 *
 * Previously a static inner class of AuthResponse.
 * Extracted to its own file because:
 *   - Single Responsibility: profile shape is its own concern
 *   - Reusable: can be used in /me endpoint, admin list, etc.
 *   - Consistent with UserProfileResponse being its own class
 */
@Getter
@Builder
@AllArgsConstructor
public class AdminProfileResponse implements ProfileResponse {

  private Long adminId;
  private String email;
  private String firstName;
  private String lastName;
  private String profileImageUrl;
  private String countryCode;
  private String phone;
  private String department;
  private String role;
  private boolean emailVerified;
}
