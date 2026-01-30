package com.railway.auth_service.entity;

import com.railway.auth_service.enums.Role;
import com.railway.auth_service.enums.Role;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "refresh_tokens", indexes = {
  @Index(name = "idx_token", columnList = "refresh_token"),
})
public class RefreshTokenEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "refresh_token", nullable = false, unique = true)
  private String refreshToken;

  // ============ OWNER INFO (USER OR ADMIN) ============

  @Column(name = "owner_id", nullable = false)
  private Long ownerId;  // Can be userId or adminId

  @Enumerated(EnumType.STRING)
  @Column(name = "owner_type", nullable = false, length = 20)
  private Role ownerType;  // USER or ADMIN

  // ============ TOKEN METADATA ============

  @Column(name = "expiry_date", nullable = false)
  private LocalDateTime expiryDate;  // When does this token expire

  @Column(name = "is_revoked", nullable = false)
  @Builder.Default
  private Boolean isRevoked = false;  // Has this token been revoked?

  @Column(name = "device_info", length = 255)
  private String deviceInfo;  // e.g., "Chrome on Windows", "Mobile App Android"

  @Column(name = "ip_address", length = 45)
  private String ipAddress;  // Track IP for security

  // ============ AUDIT ============

  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Column(name = "last_used_at")
  private LocalDateTime lastUsedAt;  // Track when token was last used

  // ============ LIFECYCLE CALLBACKS ============

  @PrePersist
  protected void onCreate() {
    createdAt = LocalDateTime.now();
    updatedAt = LocalDateTime.now();
  }

  @PreUpdate
  protected void onUpdate() {
    updatedAt = LocalDateTime.now();
  }

  // ============ HELPER METHODS ============

  public boolean isRefreshTokenExpired() {
    return LocalDateTime.now().isAfter(this.expiryDate);
  }

  public boolean isRefreshTokenValid() {
    return !isRefreshTokenExpired() && !isRevoked;
  }

  public void revokeRefreshToken() {
    this.isRevoked = true;
  }

  public void updateLastUsedRefreshToken() {
    this.lastUsedAt = LocalDateTime.now();
  }

  public boolean isUser() {
    return Role.USER.equals(this.ownerType);
  }

  public boolean isAdmin() {
    return Role.ADMIN.equals(this.ownerType);
  }
  public boolean isSuperAdmin() {
    return Role.SUPER_ADMIN.equals(this.ownerType);
  }
}
