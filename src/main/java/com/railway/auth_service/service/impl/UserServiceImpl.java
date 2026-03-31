package com.railway.auth_service.service.impl;

import com.railway.auth_service.config.properties.OtpProperties;
import com.railway.auth_service.dto.request.ChangePasswordRequest;
import com.railway.auth_service.dto.response.RegisterInitiateResponse;
import com.railway.auth_service.dto.response.UserProfileResponse;
import com.railway.auth_service.mapper.UserMapper;
import com.railway.auth_service.model.entity.RefreshToken;
import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.enums.ActorType;
import com.railway.auth_service.model.enums.UserStatus;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.auth_service.service.UserService;
import com.railway.auth_service.service.otp.OtpService;
import com.railway.auth_service.service.status.UserStatusService;
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
  private final OtpService otpService;
  private final OtpProperties otpProperties;
  private final UserStatusService userStatusService;

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


  // ═══════════════════════════════════════════
//  EMAIL VERIFICATION
// ═══════════════════════════════════════════

  @Override
  public RegisterInitiateResponse sendEmailOtp(Long userId) {

    User user = userRepository.findById(userId)
      .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

    // Already verified — no need to send OTP
    if (user.isEmailVerified()) {
      throw new BadRequestException("Email is already verified");
    }

    int expirySeconds = otpService.generateAndSendEmailOtp(user.getEmail(), userId);

    return RegisterInitiateResponse.builder()
      .message("OTP sent to " + maskEmail(user.getEmail()))
      .expiresInSeconds(expirySeconds)
      .otpLength(otpProperties.getLength())
      .build();
  }

  @Override
  @Transactional
  public void verifyEmailOtp(Long userId, String otp) {

    User user = userRepository.findById(userId)
      .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

    if (user.isEmailVerified()) {
      throw new BadRequestException("Email is already verified");
    }

    // Verify OTP — returns userId from Redis (we verify it matches)
    Long verifiedUserId = otpService.verifyEmailOtp(user.getEmail(), otp);

    // Safety check — the OTP was generated for THIS user
    if (!verifiedUserId.equals(userId)) {
      throw new UnauthorizedException("OTP does not belong to this user");
    }

    // Update email verification status
    user.setEmailVerified(true);
    userRepository.save(user);

    log.info("Email verified for userId={}", userId);
  }

  @Override
  public RegisterInitiateResponse resendEmailOtp(Long userId) {

    User user = userRepository.findById(userId)
      .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

    if (user.isEmailVerified()) {
      throw new BadRequestException("Email is already verified");
    }

    int expirySeconds = otpService.resendEmailOtp(user.getEmail(), userId);

    return RegisterInitiateResponse.builder()
      .message("OTP resent to " + maskEmail(user.getEmail()))
      .expiresInSeconds(expirySeconds)
      .otpLength(otpProperties.getLength())
      .build();
  }

  private String maskEmail(String email) {
    if (email == null || !email.contains("@")) return "****";
    int atIndex = email.indexOf("@");
    String local = email.substring(0, atIndex);
    String domain = email.substring(atIndex);
    if (local.length() <= 2) return local + "****" + domain;
    return local.substring(0, 2) + "****" + domain;
  }

  @Override
  @Transactional
  public void deactivate(Long userId, String password, String ipAddress) {

    User user = userRepository.findById(userId)
      .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

    // Can only deactivate an ACTIVE account
    if (user.getStatus() != UserStatus.ACTIVE) {
      throw new BadRequestException("Account is not active. Current status: " + user.getStatus());
    }

    // Verify password — prevent accidental or unauthorized deactivation
    if (!passwordEncoder.matches(password, user.getPasswordHash())) {
      throw new UnauthorizedException("Incorrect password");
    }

    // Change status — kills sessions + logs history async
    userStatusService.changeStatus(
      user,
      UserStatus.DEACTIVATED,
      "User requested deactivation",
      userId,
      ActorType.USER,
      ipAddress,
      true    // kill sessions
    );

    log.info("User deactivated: userId={}", userId);
  }



}
