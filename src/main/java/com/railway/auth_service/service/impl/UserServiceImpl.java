package com.railway.auth_service.service.impl;

import com.railway.auth_service.model.entity.RefreshToken;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.service.UserService;
import com.railway.common.exception.ForbiddenException;
import com.railway.common.exception.UnauthorizedException;
import com.railway.common.security.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

  private final RefreshTokenRepository refreshTokenRepository;
  private final Optional<TokenBlacklistService> blacklistService;

  @Value("${app.jwt.access-token-expiry}")
  private long accessTokenExpiry;

  @Override
  @Transactional
  public void logout(String refreshTokenStr, Long userId) {

    // Step 1: Find refresh token in DB
    RefreshToken storedToken = refreshTokenRepository.findByRefreshToken(refreshTokenStr)
      .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

    // Step 2: Verify token belongs to requesting user
    // userId comes from JWT access token (set by JWT filter → AuthPrincipal)
    // storedToken.ownerId comes from DB
    // Must match — prevents user A from revoking user B's token
    if (!storedToken.getOwnerId().equals(userId) || !"user".equals(storedToken.getOwnerType())) {
      log.warn("Logout attempt with another user's token: requester={}, token_owner={}",
        userId, storedToken.getOwnerId());
      throw new ForbiddenException("This token does not belong to you");
    }

    // Step 3: Revoke and blacklist
    if (!storedToken.isRevoked()) {
      storedToken.setRevoked(true);
      refreshTokenRepository.save(storedToken);

      // Blacklist access token for instant invalidation
      // Without this, access token works for up to 15 min after logout
      blacklistService.ifPresent(service ->
        service.setCutoff("user", userId, Duration.ofMillis(accessTokenExpiry))
      );

      log.info("User logged out: user_id={}", userId);
    }
  }
}
