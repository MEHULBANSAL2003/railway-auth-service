package com.railway.auth_service.model.entity;

import com.railway.auth_service.model.enums.UserStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.time.LocalDate;

@Entity
@Table(
  name = "users",
  schema = "railway_auth",
  uniqueConstraints = {
    @UniqueConstraint(name = "uk_users_username", columnNames = "username"),
    @UniqueConstraint(name = "uk_users_email", columnNames = "email"),
    @UniqueConstraint(name = "uk_users_phone", columnNames = "phone")
  },
  indexes = {
    @Index(name = "idx_users_username", columnList = "username"),
    @Index(name = "idx_users_email", columnList = "email"),
    @Index(name = "idx_users_phone", columnList = "phone"),
    @Index(name = "idx_users_status", columnList = "status"),
    @Index(name = "idx_users_created_at", columnList = "created_at"),
    @Index(name = "idx_users_last_login", columnList = "last_login_at")
  }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "user_id")
  private Long userId;

  // ── Identity ──

  @Column(nullable = false, length = 30)
  private String username;

  @Column(name = "full_name", nullable = false, length = 200)
  private String fullName;

  @Column(nullable = false, length = 255)
  private String email;

  @Column(name = "country_code", nullable = false, length = 5)
  @Builder.Default
  private String countryCode = "+91";

  @Column(nullable = false, length = 10)
  private String phone;

  @Column(name = "password_hash", nullable = false, length = 255)
  private String passwordHash;

  // ── Verification ──

  @Column(name = "is_email_verified", nullable = false)
  @Builder.Default
  private boolean emailVerified = false;

  @Column(name = "is_phone_verified", nullable = false)
  @Builder.Default
  private boolean phoneVerified = false;

  // ── Account Status ──

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  @Builder.Default
  private UserStatus status = UserStatus.ACTIVE;

  @Column(name = "status_reason", length = 500)
  private String statusReason;

  // ── Last Login Info ──

  @Column(name = "last_login_at")
  private Instant lastLoginAt;

  @Column(name = "last_login_ip", length = 45)
  private String lastLoginIp;

  // ── Last Device Info ──

  @Column(name = "last_device_type", length = 20)
  private String lastDeviceType;

  @Column(name = "last_os", length = 50)
  private String lastOs;

  @Column(name = "last_browser", length = 50)
  private String lastBrowser;

  // ── Last Location (from IP geolocation) ──

  @Column(name = "last_login_city", length = 100)
  private String lastLoginCity;

  @Column(name = "last_login_state", length = 100)
  private String lastLoginState;

  @Column(name = "last_login_country", length = 100)
  private String lastLoginCountry;

  // ── Password Change Tracking ──

  @Column(name = "password_change_count", nullable = false)
  @Builder.Default
  private int passwordChangeCount = 0;

  @Column(name = "last_password_change_at")
  private Instant lastPasswordChangeAt;

  // ── Profile (optional) ──

  @Column(name = "profile_image_url", length = 500)
  private String profileImageUrl;

  @Column(name = "date_of_birth")
  private LocalDate dateOfBirth;

  @Column(length = 10)
  private String gender;

  // ── Timestamps ──

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;
}
