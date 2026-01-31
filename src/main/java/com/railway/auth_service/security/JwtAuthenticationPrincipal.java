package com.railway.auth_service.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Custom Principal object that holds JWT token information
 *
 * This is stored in SecurityContext and can be retrieved in controllers/services
 * to identify the current user/admin.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtAuthenticationPrincipal implements Serializable {

  /**
   * User ID or Admin ID (depending on type)
   */
  private Long id;

  /**
   * Email from JWT token
   */
  private String email;

  /**
   * Token type: "USER" or "ADMIN"
   */
  private String type;

  /**
   * Role: "USER", "ADMIN", or "SUPER_ADMIN"
   */
  private String role;

  /**
   * Check if this is a user token
   */
  public boolean isUser() {
    return "USER".equals(type);
  }

  /**
   * Check if this is an admin token
   */
  public boolean isAdmin() {
    return "ADMIN".equals(type);
  }

  /**
   * Check if this is a super admin
   */
  public boolean isSuperAdmin() {
    return "ADMIN".equals(type) && "SUPER_ADMIN".equals(role);
  }
}
