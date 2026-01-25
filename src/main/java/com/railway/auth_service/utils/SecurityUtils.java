package com.railway.auth_service.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

public class SecurityUtils {

  public static Long getCurrentUserId() {
    Authentication authentication = SecurityContextHolder
      .getContext()
      .getAuthentication();

    if (authentication != null
      && authentication.isAuthenticated()
      && authentication.getPrincipal() instanceof Long) {
      return (Long) authentication.getPrincipal();
    }
    return null;
  }

  public static String getCurrentUsername() {
    Authentication authentication = SecurityContextHolder
      .getContext()
      .getAuthentication();

    if (authentication != null && authentication.isAuthenticated()) {
      Object principal = authentication.getPrincipal();

      if (principal instanceof UserDetails) {
        return ((UserDetails) principal).getUsername();
      } else if (principal instanceof String) {
        return (String) principal;
      }
    }
    return null;
  }

  public static Authentication getAuthentication() {
    return SecurityContextHolder.getContext().getAuthentication();
  }

  public static boolean isAuthenticated() {
    Authentication authentication = getAuthentication();
    return authentication != null
      && authentication.isAuthenticated()
      && !"anonymousUser".equals(authentication.getPrincipal());
  }

  public static boolean hasRole(String role) {
    Authentication authentication = getAuthentication();
    if (authentication == null) {
      return false;
    }

    String roleWithPrefix = role.startsWith("ROLE_") ? role : "ROLE_" + role;
    return authentication.getAuthorities().stream()
      .anyMatch(authority -> authority.getAuthority().equals(roleWithPrefix));
  }

  public static boolean hasAnyRole(String... roles) {
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
  }

  public static void clearAuthentication() {
    SecurityContextHolder.clearContext();
  }
}
