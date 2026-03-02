package com.railway.auth_service.dto.response.admin;

import com.railway.common.enums.Department;
import com.railway.common.enums.Role;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class AdminSummaryResponse {

  private Long        id;
  private String      fullName;
  private String      email;
  private String      countryCode;
  private String      phoneNumber;
  private Role        adminRole;
  private Department  department;
  private Boolean     isActive;
  private String      profilePictureUrl;
  private boolean canUpdatedByCurrentAdmin;
  private boolean canDeletedByCurrentAdmin;
  private LocalDateTime lastLoginAt;
  private LocalDateTime createdAt;
}
