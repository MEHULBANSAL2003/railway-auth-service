package com.railway.auth_service.repository;

import com.railway.auth_service.entity.RefreshTokenEntity;
import com.railway.common.enums.Role;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {

  Optional<RefreshTokenEntity> findByRefreshToken(String token);

  /**
   * Find all tokens for a user
   */
  List<RefreshTokenEntity> findByOwnerIdAndOwnerType(Long ownerId, Role ownerType);

  /**
   * Find all valid (non-revoked, non-expired) tokens for a user
   */
  @Query("SELECT rt FROM RefreshTokenEntity rt WHERE rt.ownerId = :ownerId " +
    "AND rt.ownerType = :ownerType " +
    "AND rt.isRevoked = false " +
    "AND rt.expiryDate > :now")
  List<RefreshTokenEntity> findValidTokens(Long ownerId, Role ownerType, LocalDateTime now);

  /**
   * Revoke all tokens for a user (logout from all devices)
   */
  @Modifying
  @Transactional
  @Query("UPDATE RefreshTokenEntity rt SET rt.isRevoked = true " +
    "WHERE rt.ownerId = :ownerId AND rt.ownerType = :ownerType")
  void revokeAllTokens(Long ownerId, Role ownerType);

  /**
   * Delete all revoked or expired tokens (cleanup job)
   */
  @Modifying
  @Transactional
  @Query("DELETE FROM RefreshTokenEntity rt WHERE rt.isRevoked = true OR rt.expiryDate < :now")
  void deleteExpiredAndRevokedTokens(LocalDateTime now);

  /**
   * Count active tokens for a user
   */
  @Query("SELECT COUNT(rt) FROM RefreshTokenEntity rt WHERE rt.ownerId = :ownerId " +
    "AND rt.ownerType = :ownerType " +
    "AND rt.isRevoked = false " +
    "AND rt.expiryDate > :now")
  Long countActiveTokens(Long ownerId, Role ownerType, LocalDateTime now);
}
