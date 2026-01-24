package com.railway.auth_service.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;


@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "refresh_tokens", indexes = {
  @Index(name = "idx_token", columnList = "token"),
  @Index(name = "idx_user_id", columnList = "userId")
})
public class RefreshTokenEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true, length = 500)
  private String token;  // The actual refresh token (JWT)

  @Column(nullable = false)
  private Long userId;  // Which user does this token belong to

  @Column(nullable = false)
  private LocalDateTime expiryDate;  // When does this token expire

  @Column(nullable = false)
  private Boolean isRevoked = false;  // Has this token been revoked?

  @Column(nullable = false)
  private LocalDateTime createdAt;

  @Column(nullable = false)
  private LocalDateTime updatedAt;

  @PrePersist
  protected void onCreate() {
    createdAt = LocalDateTime.now();
    updatedAt = LocalDateTime.now();
    if (isRevoked == null) {
      isRevoked = false;
    }
  }

  @PreUpdate
  protected void onUpdate() {
    updatedAt = LocalDateTime.now();
  }

  /**
   * Check if token is expired
   */
  public boolean isRefreshTokenExpired() {
    return LocalDateTime.now().isAfter(this.expiryDate);
  }

  /**
   * Check if token is valid (not expired and not revoked)
   */
  public boolean isRefreshTokenValid() {
    return !isRefreshTokenExpired() && !isRevoked;
  }
}
