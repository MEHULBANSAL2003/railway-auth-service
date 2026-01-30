package com.railway.auth_service.service.refreshTokenService;

import com.railway.auth_service.entity.RefreshTokenEntity;
import com.railway.auth_service.entity.UserEntity;
import com.railway.auth_service.exception.BaseException;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserAdminRepository;
import com.railway.auth_service.service.jwtService.JwtService;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

  private final RefreshTokenRepository refreshTokenRepository;
  private final UserAdminRepository userAdminRepository;
  private final JwtService jwtService;

  @Value("${jwt.refresh-token.expiry-ms}")
  private Long refreshTokenExpiryMs;

  @Transactional
  public RefreshTokenEntity createRefreshToken(Long userId) {
    log.debug("Creating refresh token for user: {}", userId);

    try {
      UserEntity user = userAdminRepository.findById(userId)
        .orElseThrow(() -> new BaseException(HttpStatus.BAD_REQUEST, "USER_NOT_FOUND", "User not found with id: " + userId));

      // Generate JWT refresh token
      String tokenString = jwtService.generateRefreshToken(user);

      // Calculate expiry date
      LocalDateTime expiryDate = LocalDateTime.now()
        .plusSeconds(refreshTokenExpiryMs / 1000);

      // Create entity
      RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
        .refreshToken(tokenString)
        .ownerId(userId)
        .expiryDate(expiryDate)
        .isRevoked(false)
        .build();

      // Save to database
      return refreshTokenRepository.save(refreshToken);

    } catch (BaseException e) {
      // Re-throw business exceptions as-is
      throw e;
    } catch (DataAccessException e) {
      log.error("Database error while creating refresh token for user: {}", userId, e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_CREATION_FAILED", "Failed to create refresh token");
    } catch (Exception e) {
      log.error("Unexpected error while creating refresh token for user: {}", userId, e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_CREATION_FAILED", "An unexpected error occurred while creating refresh token");
    }
  }

  /**
   * Verify refresh token and return entity
   */
  @Transactional(readOnly = true)
  public RefreshTokenEntity verifyRefreshToken(String token) {
    log.debug("Verifying refresh token");

    try {
      // Find token in database
      RefreshTokenEntity refreshToken = refreshTokenRepository.findByToken(token)
        .orElseThrow(() -> new BaseException(HttpStatus.UNAUTHORIZED, "TOKEN_NOT_FOUND", "Refresh token not found"));

      // Check if token is revoked
      if (refreshToken.getIsRevoked()) {
        log.warn("Attempted to use revoked refresh token for user: {}", refreshToken.getOwnerId());
        throw new BaseException(HttpStatus.UNAUTHORIZED, "TOKEN_REVOKED", "Refresh token revoked");
      }

      // Check if token is expired
      if (refreshToken.isRefreshTokenExpired()) {
        log.warn("Expired refresh token used for user: {}", refreshToken.getOwnerId());
        refreshTokenRepository.delete(refreshToken);
        throw new BaseException(HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED", "Refresh token has expired. Please login again.");
      }

      // Verify JWT signature
      try {
        jwtService.validateToken(token);
      } catch (Exception e) {
        log.error("Invalid refresh token JWT: {}", e.getMessage());
        throw new BaseException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "Invalid refresh token");
      }

      log.debug("Refresh token verified successfully for user: {}", refreshToken.getOwnerId());
      return refreshToken;

    } catch (BaseException e) {
      // Re-throw business exceptions as-is
      throw e;
    } catch (DataAccessException e) {
      log.error("Database error while verifying refresh token", e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_VERIFICATION_FAILED", "Failed to verify refresh token");
    } catch (Exception e) {
      log.error("Unexpected error while verifying refresh token", e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_VERIFICATION_FAILED", "An unexpected error occurred while verifying refresh token");
    }
  }

  @Transactional
  public void revokeRefreshToken(String token) {
    log.debug("Revoking refresh token");

    try {
      RefreshTokenEntity refreshToken = refreshTokenRepository.findByToken(token)
        .orElseThrow(() -> new BaseException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "Invalid refresh token"));

      refreshToken.setIsRevoked(true);
      refreshTokenRepository.save(refreshToken);

      log.info("Refresh token revoked for user: {}", refreshToken.getOwnerId());

    } catch (BaseException e) {
      // Re-throw business exceptions as-is
      throw e;
    } catch (DataAccessException e) {
      log.error("Database error while revoking refresh token", e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_REVOCATION_FAILED", "Failed to revoke refresh token");
    } catch (Exception e) {
      log.error("Unexpected error while revoking refresh token", e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_REVOCATION_FAILED", "An unexpected error occurred while revoking refresh token");
    }
  }

  @Transactional
  public void revokeAllUserTokens(Long userId) {
    log.info("Revoking all refresh tokens for user: {}", userId);

    try {
      refreshTokenRepository.revokeAllTokens(userId);
      log.info("Successfully revoked all tokens for user: {}", userId);

    } catch (DataAccessException e) {
      log.error("Database error while revoking all tokens for user: {}", userId, e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_REVOCATION_FAILED", "Failed to revoke all refresh tokens");
    } catch (Exception e) {
      log.error("Unexpected error while revoking all tokens for user: {}", userId, e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_REVOCATION_FAILED", "An unexpected error occurred while revoking all refresh tokens");
    }
  }

  @Transactional
  public void deleteExpiredTokens() {
    log.info("Deleting expired refresh tokens");

    try {
      refreshTokenRepository.deleteExpiredAndRevokedTokens(LocalDateTime.now());
      log.info("Successfully deleted expired tokens");

    } catch (DataAccessException e) {
      log.error("Database error while deleting expired tokens", e);
      // For background cleanup tasks, you might want to just log and not throw
      // Or throw if you want the scheduler to know it failed and potentially retry
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_CLEANUP_FAILED", "Failed to delete expired tokens");
    } catch (Exception e) {
      log.error("Unexpected error while deleting expired tokens", e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_CLEANUP_FAILED", "An unexpected error occurred while deleting expired tokens");
    }
  }

  @Transactional
  public RefreshTokenEntity rotateRefreshToken(String oldToken) {
    log.debug("Rotating refresh token");

    try {
      RefreshTokenEntity oldRefreshToken = verifyRefreshToken(oldToken);

      // Revoke old token
      oldRefreshToken.setIsRevoked(true);
      refreshTokenRepository.save(oldRefreshToken);

      RefreshTokenEntity newRefreshToken = createRefreshToken(oldRefreshToken.getOwnerId());

      log.info("Refresh token rotated for user: {}", oldRefreshToken.getOwnerId());
      return newRefreshToken;

    } catch (BaseException e) {
      // Re-throw business exceptions as-is
      throw e;
    } catch (DataAccessException e) {
      log.error("Database error while rotating refresh token", e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_ROTATION_FAILED", "Failed to rotate refresh token");
    } catch (Exception e) {
      log.error("Unexpected error while rotating refresh token", e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "TOKEN_ROTATION_FAILED", "An unexpected error occurred while rotating refresh token");
    }
  }
}
