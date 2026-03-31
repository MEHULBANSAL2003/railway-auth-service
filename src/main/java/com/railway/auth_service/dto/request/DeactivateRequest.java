package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * Request body for POST /api/user/deactivate
 *
 * Requires password confirmation to prevent accidental deactivation.
 * If someone has access to an unlocked phone/browser with active session,
 * they still can't deactivate without knowing the password.
 */
@Getter
@Setter
public class DeactivateRequest {

  @NotBlank(message = "Password is required to confirm deactivation")
  private String password;
}
