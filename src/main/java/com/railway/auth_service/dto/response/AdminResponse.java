package com.railway.auth_service.dto.response;

import com.railway.auth_service.model.enums.AdminRole;
import com.railway.auth_service.model.enums.Department;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

@Getter
@Builder
@AllArgsConstructor
public class AdminResponse {

  private Long adminId;
  private String email;
  private String firstName;
  private String lastName;
  private String profileImageUrl;
  private String countryCode;
  private String phone;
  private Department department;
  private AdminRole role;
  private boolean emailVerified;
  private boolean enabled;
  private Instant lastLoginAt;
  private Instant createdAt;
  private Long createdBy;
}
