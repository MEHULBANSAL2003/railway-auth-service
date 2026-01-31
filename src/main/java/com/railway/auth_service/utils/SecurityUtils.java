package com.railway.auth_service.utils;

import com.railway.auth_service.enums.Role;
import com.railway.auth_service.security.JwtAuthenticationPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * Security utility class for accessing current authenticated user/admin information
 *
 * This class provides helper methods to extract information from SecurityContext
 * which is populated by JwtAuthenticationFilter.
 */
@Slf4j
public class SecurityUtils {

  // ============ PRINCIPAL EXTRACTION ============

  /**
   * Get the current authenticated principal (user or admin)
   * Returns null if not authenticated
   */
  public static JwtAuthenticationPrincipal getCurrentPrincipal() {
    try {
      Authentication authentication = getAuthentication();

      if (authentication != null
        && authentication.isAuthenticated()
        && authentication.getPrincipal() instanceof JwtAuthenticationPrincipal) {
        return (JwtAuthenticationPrincipal) authentication.getPrincipal();
      }
    } catch (Exception e) {
      log.error("Error getting current principal", e);
    }
    return null;
  }

  /**
   * Get the current authenticated principal as Optional
   */
  public static Optional<JwtAuthenticationPrincipal> getCurrentPrincipalOptional() {
    return Optional.ofNullable(getCurrentPrincipal());
  }

  // ============ ID EXTRACTION ============

  /**
   * Get current user/admin ID
   * Returns null if not authenticated
   */
  public static Long getCurrentId() {
    JwtAuthenticationPrincipal principal = getCurrentPrincipal();
    return principal != null ? principal.getId() : null;
  }

  /**
   * Get current user ID (only if authenticated as USER)
   * Returns null if not a user or not authenticated
   */
  public static Long getCurrentUserId() {
    JwtAuthenticationPrincipal principal = getCurrentPrincipal();
    return (principal != null && principal.isUser()) ? principal.getId() : null;
  }

  /**
   * Get current admin ID (only if authenticated as ADMIN)
   * Returns null if not an admin or not authenticated
   */
  public static Long getCurrentAdminId() {
    JwtAuthenticationPrincipal principal = getCurrentPrincipal();
    return (principal != null && principal.isAdmin()) ? principal.getId() : null;
  }

  // ============ EMAIL EXTRACTION ============

  /**
   * Get current user/admin email
   * Returns null if not authenticated
   */
  public static String getCurrentEmail() {
    JwtAuthenticationPrincipal principal = getCurrentPrincipal();
    return principal != null ? principal.getEmail() : null;
  }

  // ============ TYPE & ROLE CHECKS ============

  /**
   * Check if current principal is a USER
   */
  public static boolean isUser() {
    JwtAuthenticationPrincipal principal = getCurrentPrincipal();
    return principal != null && principal.isUser();
  }

  /**
   * Check if current principal is an ADMIN (ADMIN or SUPER_ADMIN)
   */
  public static boolean isAdmin() {
    JwtAuthenticationPrincipal principal = getCurrentPrincipal();
    return principal != null && principal.isAdmin();
  }

  /**
   * Check if current principal is a SUPER_ADMIN
   */
  public static boolean isSuperAdmin() {
    JwtAuthenticationPrincipal principal = getCurrentPrincipal();
    return principal != null && principal.isSuperAdmin();
  }

  /**
   * Get current role
   * Returns null if not authenticated
   */
  public static String getCurrentRole() {
    JwtAuthenticationPrincipal principal = getCurrentPrincipal();
    return principal != null ? principal.getRole() : null;
  }

  /**
   * Get current role as enum
   * Returns null if not authenticated
   */
  public static Role getCurrentRoleEnum() {
    String role = getCurrentRole();
    try {
      return role != null ? Role.valueOf(role) : null;
    } catch (IllegalArgumentException e) {
      log.error("Invalid role: {}", role);
      return null;
    }
  }

  // ============ AUTHENTICATION CHECKS ============

  /**
   * Get current authentication object
   */
  public static Authentication getAuthentication() {
    return SecurityContextHolder.getContext().getAuthentication();
  }

  /**
   * Check if user is authenticated
   */
  public static boolean isAuthenticated() {
    try {
      Authentication authentication = getAuthentication();
      return authentication != null
        && authentication.isAuthenticated()
        && !"anonymousUser".equals(authentication.getPrincipal());
    } catch (Exception e) {
      log.error("Error checking authentication", e);
      return false;
    }
  }

  // ============ ROLE-BASED CHECKS ============

  /**
   * Check if current user has specific role
   * Automatically adds "ROLE_" prefix if not present
   */
  public static boolean hasRole(String role) {
    try {
      Authentication authentication = getAuthentication();
      if (authentication == null) {
        return false;
      }

      String roleWithPrefix = role.startsWith("ROLE_") ? role : "ROLE_" + role;

      return authentication.getAuthorities().stream()
        .anyMatch(authority -> authority.getAuthority().equals(roleWithPrefix));
    } catch (Exception e) {
      log.error("Error checking role: {}", role, e);
      return false;
    }
  }

  /**
   * Check if current user has any of the specified roles
   */
  public static boolean hasAnyRole(String... roles) {
    try {
      Authentication authentication = getAuthentication();
      if (authentication == null) {
        return false;
      }

      for (String role : roles) {
        String roleWithPrefix = role.startsWith("ROLE_") ? role : "ROLE_" + role;
        if (authentication.getAuthorities().stream()
          .anyMatch(authority -> authority.getAuthority().equals(roleWithPrefix))) {
          return true;
        }
      }
      return false;
    } catch (Exception e) {
      log.error("Error checking roles", e);
      return false;
    }
  }

  /**
   * Check if current user has all specified roles
   */
  public static boolean hasAllRoles(String... roles) {
    try {
      Authentication authentication = getAuthentication();
      if (authentication == null) {
        return false;
      }

      for (String role : roles) {
        String roleWithPrefix = role.startsWith("ROLE_") ? role : "ROLE_" + role;
        boolean hasRole = authentication.getAuthorities().stream()
          .anyMatch(authority -> authority.getAuthority().equals(roleWithPrefix));

        if (!hasRole) {
          return false;
        }
      }
      return true;
    } catch (Exception e) {
      log.error("Error checking roles", e);
      return false;
    }
  }

  /**
   * Get all roles/authorities of current user
   */
  public static String[] getCurrentAuthorities() {
    try {
      Authentication authentication = getAuthentication();
      if (authentication == null) {
        return new String[0];
      }

      return authentication.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .toArray(String[]::new);
    } catch (Exception e) {
      log.error("Error getting authorities", e);
      return new String[0];
    }
  }

  // ============ CONTEXT MANAGEMENT ============

  /**
   * Clear authentication context (useful for logout)
   */
  public static void clearAuthentication() {
    SecurityContextHolder.clearContext();
  }

  // ============ VALIDATION HELPERS ============

  /**
   * Validate that current user matches the given user ID
   * Useful for ensuring users can only access their own data
   */
  public static boolean isCurrentUser(Long userId) {
    Long currentUserId = getCurrentUserId();
    return currentUserId != null && currentUserId.equals(userId);
  }

  /**
   * Validate that current admin matches the given admin ID
   */
  public static boolean isCurrentAdmin(Long adminId) {
    Long currentAdminId = getCurrentAdminId();
    return currentAdminId != null && currentAdminId.equals(adminId);
  }

  /**
   * Check if current user can access resource
   * Users can access their own data, admins can access any data
   */
  public static boolean canAccessUserData(Long userId) {
    return isAdmin() || isCurrentUser(userId);
  }
}
