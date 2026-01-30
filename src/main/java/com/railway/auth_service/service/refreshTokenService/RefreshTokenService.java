package com.railway.auth_service.service.refreshTokenService;

import com.railway.auth_service.entity.AdminEntity;
import com.railway.auth_service.entity.RefreshTokenEntity;
import com.railway.auth_service.entity.UserEntity;
import com.railway.auth_service.enums.Role;
import com.railway.auth_service.exception.BaseException;
import com.railway.auth_service.repository.AdminRepository;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.auth_service.service.jwtService.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

  private final RefreshTokenRepository refreshTokenRepository;
  private final UserRepository userRepository;
  private final AdminRepository adminRepository;
  private final JwtService jwtService;

  @Value("${jwt.refresh-token.expiry-ms}")
  private Long refreshTokenExpiryMs;

  /**
   * Create refresh token for USER
   */
  @Transactional
  public RefreshTokenEntity createRefreshTokenForUser(Long userId) {
    log.debug("Creating refresh token for user: {}", userId);

    try {
      UserEntity user = userRepository.findById(userId)
        .orElseThrow(() -> new BaseException(
          HttpStatus.BAD_REQUEST,
          "USER_NOT_FOUND",
          "User not found with id: " + userId
        ));

      // Generate JWT refresh token for USER
      String tokenString = jwtService.generateRefreshToken(userId, user.getEmail(), Role.USER, "USER");

      // Calculate expiry date
      LocalDateTime expiryDate = LocalDateTime.now()
        .plusSeconds(refreshTokenExpiryMs / 1000);

      // Create entity
      RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
        .refreshToken(tokenString)
        .ownerId(userId)
        .ownerType(Role.USER)
        .expiryDate(expiryDate)
        .isRevoked(false)
        .build();

      // Save to database
      RefreshTokenEntity saved = refreshTokenRepository.save(refreshToken);
      log.info("Refresh token created for user: {}", userId);
      return saved;

    } catch (BaseException e) {
      throw e;
    } catch (DataAccessException e) {
      log.error("Database error while creating refresh token for user: {}", userId, e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_CREATION_FAILED",
        "Failed to create refresh token"
      );
    } catch (Exception e) {
      log.error("Unexpected error while creating refresh token for user: {}", userId, e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_CREATION_FAILED",
        "An unexpected error occurred while creating refresh token"
      );
    }
  }

  /**
   * Create refresh token for ADMIN
   */
  @Transactional
  public RefreshTokenEntity createRefreshTokenForAdmin(Long adminId) {
    log.debug("Creating refresh token for admin: {}", adminId);

    try {
      AdminEntity admin = adminRepository.findById(adminId)
        .orElseThrow(() -> new BaseException(
          HttpStatus.BAD_REQUEST,
          "ADMIN_NOT_FOUND",
          "Admin not found with id: " + adminId
        ));

      // Determine role based on admin privileges
      Role role = admin.getAdminRole();

      // Generate JWT refresh token for ADMIN
      String tokenString = jwtService.generateRefreshToken(adminId, admin.getEmail(), role, "ADMIN");

      // Calculate expiry date
      LocalDateTime expiryDate = LocalDateTime.now()
        .plusSeconds(refreshTokenExpiryMs / 1000);

      // Create entity
      RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
        .refreshToken(tokenString)
        .ownerId(adminId)
        .ownerType(role)
        .expiryDate(expiryDate)
        .isRevoked(false)
        .build();

      // Save to database
      RefreshTokenEntity saved = refreshTokenRepository.save(refreshToken);
      log.info("Refresh token created for admin: {} with role: {}", adminId, role);
      return saved;

    } catch (BaseException e) {
      throw e;
    } catch (DataAccessException e) {
      log.error("Database error while creating refresh token for admin: {}", adminId, e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_CREATION_FAILED",
        "Failed to create refresh token"
      );
    } catch (Exception e) {
      log.error("Unexpected error while creating refresh token for admin: {}", adminId, e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_CREATION_FAILED",
        "An unexpected error occurred while creating refresh token"
      );
    }
  }


  @Transactional(readOnly = true)
  public RefreshTokenEntity verifyRefreshToken(String token) {
    log.debug("Verifying refresh token");

    try {
      // Find token in database
      RefreshTokenEntity refreshToken = refreshTokenRepository.findByRefreshToken(token)
        .orElseThrow(() -> new BaseException(
          HttpStatus.UNAUTHORIZED,
          "TOKEN_NOT_FOUND",
          "Refresh token not found"
        ));

      // Check if token is revoked
      if (refreshToken.getIsRevoked()) {
        log.warn("Attempted to use revoked refresh token for {}: {}",
          refreshToken.getOwnerType(), refreshToken.getOwnerId());
        throw new BaseException(
          HttpStatus.UNAUTHORIZED,
          "TOKEN_REVOKED",
          "Refresh token has been revoked"
        );
      }

      // Check if token is expired
      if (refreshToken.isRefreshTokenExpired()) {
        log.warn("Expired refresh token used for {}: {}",
          refreshToken.getOwnerType(), refreshToken.getOwnerId());
        // Auto-delete expired token
        refreshTokenRepository.delete(refreshToken);
        throw new BaseException(
          HttpStatus.UNAUTHORIZED,
          "TOKEN_EXPIRED",
          "Refresh token has expired. Please login again."
        );
      }

      // Verify JWT signature and claims
      try {
        jwtService.validateToken(token);
      } catch (Exception e) {
        log.error("Invalid refresh token JWT: {}", e.getMessage());
        throw new BaseException(
          HttpStatus.UNAUTHORIZED,
          "INVALID_TOKEN",
          "Invalid refresh token"
        );
      }
      log.debug("Refresh token verified successfully for {}: {}", refreshToken.getOwnerType(), refreshToken.getOwnerId());
      return refreshToken;

    } catch (BaseException e) {
      throw e;
    } catch (DataAccessException e) {
      log.error("Database error while verifying refresh token", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_VERIFICATION_FAILED",
        "Failed to verify refresh token"
      );
    } catch (Exception e) {
      log.error("Unexpected error while verifying refresh token", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_VERIFICATION_FAILED",
        "An unexpected error occurred while verifying refresh token"
      );
    }
  }

  /**
   * Revoke a single refresh token (logout from current device)
   */
  @Transactional
  public void revokeRefreshToken(String token) {
    log.debug("Revoking refresh token");

    try {
      RefreshTokenEntity refreshToken = refreshTokenRepository.findByRefreshToken(token)
        .orElseThrow(() -> new BaseException(
          HttpStatus.UNAUTHORIZED,
          "INVALID_TOKEN",
          "Invalid refresh token"
        ));

      refreshToken.revokeRefreshToken();
      refreshTokenRepository.save(refreshToken);

      log.info("Refresh token revoked for {}: {}",
        refreshToken.getOwnerType(), refreshToken.getOwnerId());

    } catch (BaseException e) {
      throw e;
    } catch (DataAccessException e) {
      log.error("Database error while revoking refresh token", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_REVOCATION_FAILED",
        "Failed to revoke refresh token"
      );
    } catch (Exception e) {
      log.error("Unexpected error while revoking refresh token", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_REVOCATION_FAILED",
        "An unexpected error occurred while revoking refresh token"
      );
    }
  }

  /**
   * Revoke all tokens for an owner (logout from all devices)
   */
  @Transactional
  public void revokeAllTokens(Long ownerId, Role ownerType) {
    log.info("Revoking all refresh tokens for {}: {}", ownerType, ownerId);

    try {
      refreshTokenRepository.revokeAllTokens(ownerId, ownerType);
      log.info("Successfully revoked all tokens for {}: {}", ownerType, ownerId);

    } catch (DataAccessException e) {
      log.error("Database error while revoking all tokens for {}: {}", ownerType, ownerId, e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_REVOCATION_FAILED",
        "Failed to revoke all refresh tokens"
      );
    } catch (Exception e) {
      log.error("Unexpected error while revoking all tokens for {}: {}", ownerType, ownerId, e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_REVOCATION_FAILED",
        "An unexpected error occurred while revoking all refresh tokens"
      );
    }
  }

  /**
   * Delete expired and revoked tokens (cleanup job)
   */
  @Transactional
  public void deleteExpiredTokens() {
    log.info("Deleting expired and revoked refresh tokens");

    try {
      refreshTokenRepository.deleteExpiredAndRevokedTokens(LocalDateTime.now());
      log.info("Successfully deleted expired and revoked tokens");

    } catch (DataAccessException e) {
      log.error("Database error while deleting expired tokens", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_CLEANUP_FAILED",
        "Failed to delete expired tokens"
      );
    } catch (Exception e) {
      log.error("Unexpected error while deleting expired tokens", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_CLEANUP_FAILED",
        "An unexpected error occurred while deleting expired tokens"
      );
    }
  }

  /**
   * Rotate refresh token (revoke old, create new)
   * Best practice for security
   */
  @Transactional
  public RefreshTokenEntity rotateRefreshToken(String oldToken) {
    log.debug("Rotating refresh token");

    try {
      RefreshTokenEntity oldRefreshToken = verifyRefreshToken(oldToken);

      // Revoke old token
      oldRefreshToken.revokeRefreshToken();
      refreshTokenRepository.save(oldRefreshToken);

      // Create new token based on owner type
      RefreshTokenEntity newRefreshToken;
      if (oldRefreshToken.isUser()) {
        newRefreshToken = createRefreshTokenForUser(oldRefreshToken.getOwnerId());
      } else {
        newRefreshToken = createRefreshTokenForAdmin(oldRefreshToken.getOwnerId());
      }

      // Copy device info from old token
      if (oldRefreshToken.getDeviceInfo() != null) {
        newRefreshToken.setDeviceInfo(oldRefreshToken.getDeviceInfo());
      }
      if (oldRefreshToken.getIpAddress() != null) {
        newRefreshToken.setIpAddress(oldRefreshToken.getIpAddress());
      }
      refreshTokenRepository.save(newRefreshToken);

      log.info("Refresh token rotated for {}: {}",
        oldRefreshToken.getOwnerType(), oldRefreshToken.getOwnerId());
      return newRefreshToken;

    } catch (BaseException e) {
      throw e;
    } catch (DataAccessException e) {
      log.error("Database error while rotating refresh token", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_ROTATION_FAILED",
        "Failed to rotate refresh token"
      );
    } catch (Exception e) {
      log.error("Unexpected error while rotating refresh token", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_ROTATION_FAILED",
        "An unexpected error occurred while rotating refresh token"
      );
    }
  }

  @Transactional(readOnly = true)
  public java.util.List<RefreshTokenEntity> getActiveSessions(Long ownerId, Role ownerType) {
    log.debug("Getting active sessions for {}: {}", ownerType, ownerId);

    try {
      return refreshTokenRepository.findValidTokens(ownerId, ownerType, LocalDateTime.now());
    } catch (Exception e) {
      log.error("Error getting active sessions", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "SESSION_FETCH_FAILED",
        "Failed to fetch active sessions"
      );
    }
  }

  /**
   * Count active tokens for an owner
   */
  @Transactional(readOnly = true)
  public Long countActiveTokens(Long ownerId, Role ownerType) {
    log.debug("Counting active tokens for {}: {}", ownerType, ownerId);

    try {
      return refreshTokenRepository.countActiveTokens(ownerId, ownerType, LocalDateTime.now());
    } catch (Exception e) {
      log.error("Error counting active tokens", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "TOKEN_COUNT_FAILED",
        "Failed to count active tokens"
      );
    }
  }


}
