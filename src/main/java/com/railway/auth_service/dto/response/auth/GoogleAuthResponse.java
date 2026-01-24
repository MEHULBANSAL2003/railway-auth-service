package com.railway.auth_service.dto.response.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.railway.auth_service.enums.Role;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GoogleAuthResponse {

  private String accessToken;
  private String refreshToken;
  private Long expiresIn;
  private Long adminId;
  private String email;
  private String name;
  private Role role;
  private String userName;
  private LocalDateTime createdAt;
  private LocalDateTime lastLoginAt;
  private String countryCode;
  private String phoneNumber;
  private String profilePicture;
  private Boolean isActive;


}
