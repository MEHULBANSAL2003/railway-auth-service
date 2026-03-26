package com.railway.auth_service.constant;

/**
 * Centralized API path constants.
 *
 * WHY constants instead of hardcoded strings?
 *   - Change a path in ONE place, all controllers update
 *   - No typo bugs ("/api/amin" vs "/api/admin")
 *   - SecurityConfig references these too — paths stay in sync
 *   - IDE autocomplete: type ApiConstants. and see all endpoints
 *
 * WHY private constructor?
 *   This class should never be instantiated — it's just a holder
 *   for static constants. Private constructor prevents accidental
 *   new ApiConstants().
 *
 * NAMING CONVENTION:
 *   AUTH_*    → authentication endpoints (login, register, logout)
 *   ADMIN_*  → admin management endpoints
 *   USER_*   → user management endpoints
 */
public final class ApiConstants {

  private ApiConstants() {
    // prevent instantiation
  }

  // ─────────────────────────────────────
  // Base paths
  // ─────────────────────────────────────
  public static final String AUTH_BASE = "/api/auth";
  public static final String ADMINS_BASE = "/api/admin";
  public static final String USERS_BASE = "/api/users";

  // ─────────────────────────────────────
  // Admin Auth (public — no token needed)
  // ─────────────────────────────────────
  public static final String ADMIN_AUTH = AUTH_BASE + "/admin";
  public static final String ADMIN_GOOGLE_LOGIN = "/login/google";
  public static final String ADMIN_REFRESH = "/refresh";
  public static final String ADMIN_LOGOUT = "/logout";


  public static final String ADMIN_BY_ID = "/{adminId}";
  public static final String ADMIN_TOGGLE_STATUS = "{adminId}/toggle-status";
  public static final String ADMIN_CHANGE_ROLE = "{adminId}/change-role";

  public static final String USER_AUTH = AUTH_BASE + "/user";
  public static final String USER_REGISTER = USER_AUTH + "/register";
  public static final String USER_LOGIN = USER_AUTH + "/login";
  public static final String USER_PHONE_LOGIN = USER_AUTH + "/phone-login";
  public static final String USER_REFRESH = USER_AUTH + "/refresh";
  public static final String USER_LOGOUT = USER_AUTH + "/logout";

  // ─────────────────────────────────────
  // Public paths (for SecurityConfig)
  // ─────────────────────────────────────
  public static final String[] PUBLIC_PATHS = {
    AUTH_BASE + "/**",
    "/actuator/**"
  };
}
