package com.railway.auth_service.dto.response.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.railway.common.enums.Department;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RefreshTokenResponse {
  private String accessToken;
  private String refreshToken;
  private Long expiresIn;
  private String ownerType;
  private Long ownerId;
  private String email;

  private Long userId;
  private String userName;


  private Long adminId;
  private String adminRole;
  private Department department;
}
