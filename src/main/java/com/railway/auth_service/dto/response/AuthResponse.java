package com.railway.auth_service.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

/**
 * Authentication response returned after successful login or registration.
 *
 * Shared between admin and user auth flows.
 * Token fields are the same for both — DRY.
 * Profile field is polymorphic — holds AdminProfileResponse or
 * UserProfileResponse based on who authenticated.
 *
 * Why not generic AuthResponse<T>?
 *   - Nested generics with ApiResponse<AuthResponse<T>> are messy
 *   - Jackson handles nested generics poorly in some cases
 *   - Swagger/OpenAPI can't document nested generics well
 *   - Marker interface achieves the same type safety without complexity
 */
@Getter
@Builder
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {

  private String accessToken;
  private String refreshToken;

  /**
   * Always "Bearer". Tells frontend how to use the token.
   * Authorization header: "Bearer eyJhb..."
   *
   * Why include if it's always the same?
   * OAuth2 spec convention. Frontend shouldn't hardcode "Bearer".
   * If you ever switch to a different token type (MAC, etc.),
   * frontend reads this field and adapts. Future-proof.
   */
  private String tokenType;

  /**
   * Access token expiry in milliseconds.
   * Frontend uses this to schedule token refresh.
   *
   * Why milliseconds and not seconds?
   * JavaScript's Date.now() returns milliseconds.
   * Frontend calculates: expiryTime = Date.now() + expiresIn.
   * No conversion needed. Consistent with JWT standard claims.
   */
  private long expiresIn;

  /**
   * Polymorphic profile — actual type depends on who authenticated.
   *
   * Admin login → AdminProfileResponse
   * User login/register → UserProfileResponse
   *
   * Jackson serializes the ACTUAL object, not the declared type.
   * So the JSON output contains all fields of the real profile class.
   *
   * @JsonInclude(NON_NULL) on the class level ensures null profile
   * is excluded from JSON (e.g., token refresh returns no profile).
   */
  private ProfileResponse profile;

  @Builder.Default
  private boolean reactivated = false;
}
