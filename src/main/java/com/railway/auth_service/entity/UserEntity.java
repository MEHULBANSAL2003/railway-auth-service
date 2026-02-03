package com.railway.auth_service.entity;
import com.railway.auth_service.enums.AuthProvider;
import com.railway.common.enums.Role;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users",indexes = {
  @Index(name = "idx_email", columnList = "email"),
  @Index(name = "idx_phone", columnList = "phone_number"),
  @Index(name = "idx_user_name", columnList = "user_name")
})
public class UserEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 100)
  @NotBlank(message = "Name is required")
  private String name;

  @Column(name = "user_name", unique = true, length = 50)
  @NotBlank(message = "Username is required")
  private String userName;

  @Column(name = "phone_number", unique = true, length = 15)
  @Pattern(regexp = "^[0-9]{10}$", message = "Phone must be 10 digits")
  private String phoneNumber;

  @Column(name = "country_code", length = 5)
  @Builder.Default
  private String countryCode = "+91";

  @Column(unique = true, length = 255)
  @Email(message = "Invalid email")
  private String email;

  @Column(name = "password_hash")
  private String passwordHash;

  @Column(name = "is_phone_verified")
  @Builder.Default
  private Boolean isPhoneVerified = false;

  @Column(name = "is_email_verified")
  @Builder.Default
  private Boolean isEmailVerified = false;

  @Column(name = "is_active", nullable = false)
  @Builder.Default
  private Boolean isActive = true;

  @Column(name = "is_blocked", nullable = false)
  @Builder.Default
  private Boolean isBlocked = false;

  @Column(name = "blocked_reason", columnDefinition = "TEXT")
  private String blockedReason;

  @Column(name = "last_login_at")
  private LocalDateTime lastLoginAt;

  @Column(name = "failed_login_attempts")
  @Builder.Default
  private Integer failedLoginAttempts = 0;

  @Column(name = "account_locked_until")
  private LocalDateTime accountLockedUntil;

  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Column(name = "deleted_at")
  private LocalDateTime deletedAt;


  @PrePersist
  protected void onCreate() {
    createdAt = LocalDateTime.now();
    updatedAt = LocalDateTime.now();
  }

  @PreUpdate
  protected void onUpdate() {
    updatedAt = LocalDateTime.now();
  }


  public boolean canLogin() {
    return isActive && !isBlocked && !isAccountLocked();
  }

  public boolean isAccountLocked() {
    return accountLockedUntil != null &&
      accountLockedUntil.isAfter(LocalDateTime.now());
  }

  public void incrementFailedLoginAttempts() {
    this.failedLoginAttempts++;
    if (this.failedLoginAttempts >= 5) {
      this.accountLockedUntil = LocalDateTime.now().plusMinutes(30);
    }
  }

  public void resetFailedLoginAttempts() {
    this.failedLoginAttempts = 0;
    this.accountLockedUntil = null;
    this.lastLoginAt = LocalDateTime.now();
  }

  public void verifyEmail() {
    this.isEmailVerified = true;
  }

  public void verifyPhone() {
    this.isPhoneVerified = true;
  }

  public void block(String reason) {
    this.isBlocked = true;
    this.blockedReason = reason;
  }

  public void unblock() {
    this.isBlocked = false;
    this.blockedReason = null;
  }

  public String getFullPhoneNumber() {
    return phoneNumber != null ? countryCode + phoneNumber : null;
  }

}
