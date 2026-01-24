package com.railway.auth_service.service.refreshTokenService;


import com.railway.auth_service.entity.RefreshTokenEntity;
import com.railway.auth_service.entity.UserEntity;
import com.railway.auth_service.exception.BaseException;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.auth_service.service.jwtService.JwtService;
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
  private final UserRepository userRepository;
  private final JwtService jwtService;

  @Value("${jwt.refresh-token.expiry-ms}")
  private Long refreshTokenExpiryMs;

  @Transactional
  public RefreshTokenEntity createRefreshToken(Long userId) {
    log.debug("Creating refresh token for user: {}", userId);

    UserEntity user = userRepository.findById(userId)
      .orElseThrow(() -> new BaseException(HttpStatus.BAD_REQUEST,"USER_NOT_FOUND","User not found with id: " + userId));

    // Generate JWT refresh token
    String tokenString = jwtService.generateRefreshToken(user);

    // Calculate expiry date
    LocalDateTime expiryDate = LocalDateTime.now()
      .plusSeconds(refreshTokenExpiryMs / 1000);

    // Create entity
    RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
      .token(tokenString)
      .userId(userId)
      .expiryDate(expiryDate)
      .isRevoked(false)
      .build();

    // Save to database
    return refreshTokenRepository.save(refreshToken);
  }

  /**
   * Verify refresh token and return entity
   */
  @Transactional(readOnly = true)
  public RefreshTokenEntity verifyRefreshToken(String token) {
    log.debug("Verifying refresh token");

    // Find token in database
    RefreshTokenEntity refreshToken = refreshTokenRepository.findByToken(token)
      .orElseThrow(() -> new BaseException(HttpStatus.UNAUTHORIZED,"TOKEN_NOT_FOUND","Refresh token not found"));

    // Check if token is revoked
    if (refreshToken.getIsRevoked()) {
      log.warn("Attempted to use revoked refresh token for user: {}", refreshToken.getUserId());
      throw new BaseException(HttpStatus.UNAUTHORIZED,"TOKEN_REVOKED","Refresh token revoked");
    }

    // Check if token is expired
    if (refreshToken.isRefreshTokenExpired()) {
      log.warn("Expired refresh token used for user: {}", refreshToken.getUserId());
      refreshTokenRepository.delete(refreshToken);
      throw new BaseException(HttpStatus.UNAUTHORIZED,"TOKEN_EXPIRED","Refresh token has expired. Please login again.");
    }

    // Verify JWT signature
    try {
      jwtService.validateToken(token);
    } catch (Exception e) {
      log.error("Invalid refresh token JWT: {}", e.getMessage());
      throw new BaseException(HttpStatus.UNAUTHORIZED,"INVALID_TOKEN","Invalid refresh token");
    }
    log.debug("Refresh token verified successfully for user: {}", refreshToken.getUserId());
    return refreshToken;
  }

  @Transactional
  public void revokeRefreshToken(String token) {
    log.debug("Revoking refresh token");

    RefreshTokenEntity refreshToken = refreshTokenRepository.findByToken(token)
      .orElseThrow(() -> new BaseException(HttpStatus.UNAUTHORIZED,"INVALID_TOKEN","Invalid refresh token"));

    refreshToken.setIsRevoked(true);
    refreshTokenRepository.save(refreshToken);

    log.info("Refresh token revoked for user: {}", refreshToken.getUserId());
  }

  @Transactional
  public void revokeAllUserTokens(Long userId) {
    log.info("Revoking all refresh tokens for user: {}", userId);
    refreshTokenRepository.revokeAllUserTokens(userId);
  }

  @Transactional
  public void deleteExpiredTokens() {
    log.info("Deleting expired refresh tokens");
    refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
  }

  @Transactional
  public RefreshTokenEntity rotateRefreshToken(String oldToken) {
    log.debug("Rotating refresh token");

    RefreshTokenEntity oldRefreshToken = verifyRefreshToken(oldToken);

    // Revoke old token
    oldRefreshToken.setIsRevoked(true);
    refreshTokenRepository.save(oldRefreshToken);

    RefreshTokenEntity newRefreshToken = createRefreshToken(oldRefreshToken.getUserId());

    log.info("Refresh token rotated for user: {}", oldRefreshToken.getUserId());
    return newRefreshToken;
  }







}
