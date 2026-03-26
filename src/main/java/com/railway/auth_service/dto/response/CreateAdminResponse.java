package com.railway.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class CreateAdminResponse {

  private String message;
  private AdminDetails admin;

  @Getter
  @Builder
  @AllArgsConstructor
  public static class AdminDetails {
    private Long adminId;
    private String email;
    private String firstName;
    private String lastName;
    private String countryCode;
    private String phone;
    private String department;
    private String role;
    private boolean emailVerified;
    private boolean enabled;
  }
}
