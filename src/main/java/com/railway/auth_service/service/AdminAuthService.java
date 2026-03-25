package com.railway.auth_service.service;

import com.railway.auth_service.dto.response.AuthResponse;

/**
 * Contract for admin authentication operations.
 *
 * WHY an interface?
 *   DEPENDENCY INVERSION (D in SOLID):
 *   - Controller depends on this interface, not the implementation
 *   - If you need a mock for testing: create MockAdminAuthService
 *   - If you change the implementation: controller doesn't change
 *   - Spring injects the @Service class that implements this
 *
 *   INTERFACE SEGREGATION (I in SOLID):
 *   - This interface has ONLY auth methods (login, refresh, logout)
 *   - Admin CRUD operations live in AdminService (separate interface)
 *   - A class that needs login shouldn't be forced to depend on
 *     admin creation/deletion methods it doesn't use
 */
public interface AdminAuthService {

  /**
   * Authenticate an admin via Google OAuth.
   *
   * @param googleIdToken the ID token from Google (frontend sends this)
   * @param clientIp      the client's IP address (for security logging)
   * @return access token, refresh token, and admin profile
   */
  AuthResponse googleLogin(String googleIdToken, String clientIp);
}
