package com.railway.auth_service.dto.response;

import com.railway.auth_service.model.enums.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.time.LocalDate;

@Getter
@Builder
@AllArgsConstructor
public class AdminUserDetailResponse {

  // ── Identity ──
  private Long userId;
  private String username;
  private String fullName;
  private String email;
  private String countryCode;
  private String phone;

  // ── Verification ──
  private boolean phoneVerified;
  private boolean emailVerified;

  // ── Account Status ──
  private UserStatus status;
  private String statusReason;

  // ── Last Login Info ──
  private Instant lastLoginAt;
  private String lastLoginIp;

  // ── Last Device Info ──
  private String lastDeviceType;
  private String lastOs;
  private String lastBrowser;

  // ── Last Location ──
  private String lastLoginCity;
  private String lastLoginState;
  private String lastLoginCountry;

  // ── Profile ──
  private String profileImageUrl;
  private LocalDate dateOfBirth;
  private String gender;

  // ── Password Change Tracking ──
  private int passwordChangeCount;
  private Instant lastPasswordChangeAt;

  // ── Timestamps ──
  private Instant createdAt;
  private Instant updatedAt;
}
