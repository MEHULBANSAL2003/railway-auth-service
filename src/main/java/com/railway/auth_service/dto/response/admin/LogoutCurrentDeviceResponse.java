package com.railway.auth_service.dto.response.admin;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LogoutCurrentDeviceResponse {

  private String message;
  private LocalDateTime timestamp;

  // Owner info
  private String ownerType;  // "USER" or "ADMIN"
  private Long ownerId;
  private String email;

  // Token info
  private String deviceInfo;
  private String ipAddress;
  private LocalDateTime lastUsedAt;
}
