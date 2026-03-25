package com.railway.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class AuthResponse {

  private String accessToken;
  private String refreshToken;
  private String tokenType;
  private long expiresIn;
  private AdminProfileResponse profile;


  @Getter
  @Builder
  @AllArgsConstructor
  public static class AdminProfileResponse {

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
}
