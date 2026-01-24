package com.railway.auth_service.repository;

import com.railway.auth_service.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {

  Optional<RefreshTokenEntity> findByToken(String token);

  /**
   * Find all refresh tokens for a user
   */
  List<RefreshTokenEntity> findByUserId(Long userId);

  /**
   * Find all valid (non-revoked, non-expired) tokens for a user
   */
  @Query("SELECT rt FROM RefreshTokenEntity rt WHERE rt.userId = :userId " +
    "AND rt.isRevoked = false AND rt.expiryDate > :now")
  List<RefreshTokenEntity> findValidTokensByUserId(Long userId, LocalDateTime now);

  /**
   * Revoke all tokens for a user (useful for logout all devices)
   */
  @Modifying
  @Query("UPDATE RefreshTokenEntity rt SET rt.isRevoked = true " +
    "WHERE rt.userId = :userId AND rt.isRevoked = false")
  void revokeAllUserTokens(Long userId);

  /**
   * Delete expired tokens (cleanup job)
   */
  @Modifying
  @Query("DELETE FROM RefreshTokenEntity rt WHERE rt.expiryDate < :now")
  void deleteExpiredTokens(LocalDateTime now);

  /**
   * Delete all tokens for a user
   */
  void deleteByUserId(Long userId);
}
