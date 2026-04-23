package com.railway.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class DeleteAccountRequest {

  @NotBlank(message = "Password is required to confirm deactivation")
  private String password;

  @NotBlank(message = "Reason is required")
  private String deleteReason;
}
