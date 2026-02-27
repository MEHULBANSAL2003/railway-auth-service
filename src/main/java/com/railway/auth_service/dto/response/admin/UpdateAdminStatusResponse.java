package com.railway.auth_service.dto.response.admin;

import com.railway.common.enums.Role;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class UpdateAdminStatusResponse {
  private Long          id;
  private String        fullName;
  private String        email;
  private Role          adminRole;
  private Boolean       isActive;
  private LocalDateTime deletedAt;   // non-null when soft-deleted
  private LocalDateTime updatedAt;
  private String        message;
}
