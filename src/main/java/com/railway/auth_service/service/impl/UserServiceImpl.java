package com.railway.auth_service.service.impl;

import com.railway.auth_service.dto.request.ChangePasswordRequest;
import com.railway.auth_service.dto.response.UserProfileResponse;
import com.railway.auth_service.mapper.UserMapper;
import com.railway.auth_service.model.entity.RefreshToken;
import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.auth_service.service.UserService;
import com.railway.common.exception.BadRequestException;
import com.railway.common.exception.ForbiddenException;
import com.railway.common.exception.ResourceNotFoundException;
import com.railway.common.exception.UnauthorizedException;
import com.railway.common.security.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

  private final RefreshTokenRepository refreshTokenRepository;
  private final Optional<TokenBlacklistService> blacklistService;
  private final UserRepository userRepository;
  private final UserMapper userMapper;
  private final PasswordEncoder passwordEncoder;

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

  @Override
  public UserProfileResponse getMyProfile(Long userId) {

    User user = userRepository.findById(userId)
      .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

    return userMapper.toProfileResponse(user);
  }

  @Override
  @Transactional
  public void changePassword(Long userId, ChangePasswordRequest request) {

    User user = userRepository.findById(userId)
      .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

    // Verify current password
    if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
      throw new BadRequestException("Current password is incorrect");
    }

    // Prevent setting the same password
    if (passwordEncoder.matches(request.getNewPassword(), user.getPasswordHash())) {
      throw new BadRequestException("New password must be different from the current password");
    }

    // Update password and tracking fields
    user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
    user.setPasswordChangeCount(user.getPasswordChangeCount() + 1);
    user.setLastPasswordChangeAt(Instant.now());
    userRepository.save(user);

    // Revoke all refresh tokens — force re-login on all devices
    refreshTokenRepository.revokeAllByOwner(userId, "user");

    // Blacklist current access tokens
    blacklistService.ifPresent(service ->
      service.setCutoff("user", userId, Duration.ofMillis(accessTokenExpiry))
    );

    log.info("Password changed for user: id={}", userId);
  }

}
