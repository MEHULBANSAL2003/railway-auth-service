package com.railway.auth_service.model.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(
  name = "refresh_tokens",
  schema = "railway_auth",
  uniqueConstraints = {
    @UniqueConstraint(name = "uk_refresh_tokens_token", columnNames = "token")
  },
  indexes = {
    @Index(name = "idx_refresh_token", columnList = "token"),
    @Index(name = "idx_refresh_owner", columnList = "owner_id, owner_type"),
    @Index(name = "idx_refresh_expires", columnList = "expires_at")
  }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "refresh_token_id")
  private Long refreshTokenId;

  @Column(name = "refresh_token", nullable = false, length = 500)
  private String refreshToken;

  @Column(name = "owner_id", nullable = false)
  private Long ownerId;

  @Column(name = "owner_type", nullable = false, length = 10)
  private String ownerType;

  @Column(name = "device_info", length = 255)
  private String deviceInfo;

  @Column(name = "ip_address", length = 45)
  private String ipAddress;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  @Column(name = "is_revoked", nullable = false)
  @Builder.Default
  private boolean revoked = false;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;
}
