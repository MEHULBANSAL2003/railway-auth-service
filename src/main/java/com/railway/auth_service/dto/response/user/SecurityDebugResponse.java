package com.railway.auth_service.dto.response.user;


import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SecurityDebugResponse {

  private Long adminId;
  private Long userId;
  private Long id;
  private boolean isAdmin;
  private String[] authorities;
  private String role;
  private boolean isAuthenticated;
}
