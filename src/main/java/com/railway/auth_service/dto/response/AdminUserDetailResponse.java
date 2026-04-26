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

  // ── Registration Metadata (set once at signup) ──
  private RegistrationMetadata registrationMetadata;

  // ── Last Login Metadata (updates on each login) ──
  private LastLoginMetadata lastLoginMetadata;

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

  // ── Deletion Info ──
  private Instant deletedAt;
  private Instant deletionScheduledAt;
  private String deletionReason;
}
