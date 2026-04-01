package com.railway.auth_service.dto.response;

import com.railway.auth_service.model.enums.ActorType;
import com.railway.auth_service.model.enums.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

@Getter
@Builder
@AllArgsConstructor
public class UserStatusHistoryResponse {

  private Long id;
  private Long userId;
  private String username;
  private String userFullName;
  private UserStatus oldStatus;
  private UserStatus newStatus;
  private String reason;
  private Long changedById;
  private String changedByName;
  private ActorType changedByType;
  private String ipAddress;
  private Instant changedAt;
}
