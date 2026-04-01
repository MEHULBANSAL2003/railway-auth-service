package com.railway.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

@Getter
@Builder
@AllArgsConstructor
public class ActiveSessionResponse {

  private Long tokenId;
  private String ipAddress;
  private String deviceInfo;
  private Instant issuedAt;
  private Instant expiresAt;
  private boolean expired;
}
