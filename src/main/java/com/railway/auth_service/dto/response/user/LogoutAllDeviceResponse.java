package com.railway.auth_service.dto.response.user;

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
public class LogoutAllDeviceResponse {

  private String message;
  private LocalDateTime timestamp;

  // Owner info
  private String ownerType;  // "USER" or "ADMIN"
  private Long ownerId;
  private String email;

  // Statistics
  private Integer devicesLoggedOut;  // Number of refresh tokens revoked
}
