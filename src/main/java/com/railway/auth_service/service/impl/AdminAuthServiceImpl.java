package com.railway.auth_service.service.impl;

import com.railway.auth_service.dto.response.AuthResponse;
import com.railway.auth_service.mapper.AdminMapper;
import com.railway.auth_service.model.entity.Admin;
import com.railway.auth_service.model.entity.RefreshToken;
import com.railway.auth_service.repository.AdminRepository;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.service.AdminAuthService;
import com.railway.auth_service.service.GoogleTokenVerifier;
import com.railway.auth_service.service.GoogleTokenVerifier.GoogleUserInfo;
import com.railway.common.exception.ForbiddenException;
import com.railway.common.exception.ResourceNotFoundException;
import com.railway.common.exception.ServiceException;
import com.railway.common.exception.UnauthorizedException;
import com.railway.common.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminAuthServiceImpl implements AdminAuthService {

  private final GoogleTokenVerifier googleTokenVerifier;
  private final AdminRepository adminRepository;
  private final RefreshTokenRepository refreshTokenRepository;
  private final JwtUtil jwtUtil;
  private final AdminMapper adminMapper;

  @Value("${app.jwt.access-token-expiry}")
  private long accessTokenExpiry;

  @Value("${app.jwt.refresh-token-expiry}")
  private long refreshTokenExpiry;

  @Override
  @Transactional
  public AuthResponse googleLogin(String googleIdToken, String clientIp) {

    // Step 1: Verify token with Google
    GoogleUserInfo googleUser = googleTokenVerifier.verify(googleIdToken);
    log.info("Google token verified for email: {}", googleUser.getEmail());

    // Step 2: Find admin by email
    Admin admin = adminRepository.findByEmail(googleUser.getEmail())
      .orElseThrow(() -> {
        log.warn("Admin login rejected — not found: {}", googleUser.getEmail());
        return new ResourceNotFoundException("Admin", "email", googleUser.getEmail());
      });

    // Step 3: Check if account is enabled
    if (!admin.isEnabled()) {
      log.warn("Admin login rejected — disabled: {}", admin.getEmail());
      throw new ForbiddenException("Your account has been disabled");
    }

    // Step 4: First login — link googleId, verify email
    if (admin.getGoogleId() == null) {
      admin.setGoogleId(googleUser.getGoogleId());
      admin.setEmailVerified(true);
      log.info("First Google login — googleId linked for admin: {}", admin.getAdminId());
    }

    // Step 5: Subsequent login — verify googleId matches
    if (!admin.getGoogleId().equals(googleUser.getGoogleId())) {
      log.warn("GoogleId mismatch for admin: {}", admin.getEmail());
      throw new ForbiddenException("Google account mismatch. Contact super admin.");
    }

    // Step 6: Revoke all existing refresh tokens (single session enforcement)
    refreshTokenRepository.revokeAllByOwner(admin.getAdminId(), "admin");
    log.debug("Revoked existing sessions for admin: {}", admin.getAdminId());

    // Step 7: Update login metadata
    boolean isFirstLogin = admin.getLastLoginAt() == null;
    admin.setLastLoginAt(Instant.now());
    admin.setLastLoginIp(clientIp);
    admin.setProfileImageUrl(googleUser.getProfileImageUrl());
    if (isFirstLogin) {
      if (googleUser.getFirstName() != null) admin.setFirstName(googleUser.getFirstName());
      if (googleUser.getLastName() != null) admin.setLastName(googleUser.getLastName());
    }

    try {
      adminRepository.save(admin);
    } catch (DataIntegrityViolationException ex) {
      log.error("Data integrity violation during admin login: {}", ex.getMessage());
      throw new ServiceException("Login failed due to a conflict. Please try again.");
    }

    // Step 8: Generate tokens
    String accessToken = jwtUtil.generateAccessToken(
      admin.getAdminId(),
      admin.getEmail(),
      admin.getRole().name(),
      "admin"
    );

    String refreshToken = jwtUtil.generateRefreshToken(
      admin.getAdminId(),
      "admin"
    );

    // Step 9: Save refresh token in DB
    RefreshToken refreshTokenEntity = RefreshToken.builder()
      .refreshToken(refreshToken)
      .ownerId(admin.getAdminId())
      .ownerType("admin")
      .ipAddress(clientIp)
      .expiresAt(Instant.now().plusMillis(refreshTokenExpiry))
      .build();

    refreshTokenRepository.save(refreshTokenEntity);
    log.info("Admin logged in: id={}, email={}, ip={}", admin.getAdminId(), admin.getEmail(), clientIp);

    // Step 10: Build response
    return AuthResponse.builder()
      .accessToken(accessToken)
      .refreshToken(refreshToken)
      .tokenType("Bearer")
      .expiresIn(accessTokenExpiry)
      .profile(adminMapper.toProfileResponse(admin))
      .build();
  }

  /**
   * Refresh tokens — issue new access + refresh token pair.
   *
   * FLOW:
   *   1. Find refresh token in DB
   *   2. Check if revoked → if yes, possible token theft — revoke ALL
   *   3. Check if expired
   *   4. Check owner type is "admin"
   *   5. Find the admin in DB (to get latest role, enabled status)
   *   6. Revoke the OLD refresh token (rotation)
   *   7. Generate new token pair
   *   8. Save new refresh token in DB
   *
   * WHY check the admin again from DB?
   *   The refresh token was issued 15 min ago. In that time:
   *     - Admin's role might have changed (demoted from SUPER_ADMIN)
   *     - Admin's account might have been disabled
   *   The new access token must reflect the CURRENT state.
   */
  @Override
  @Transactional
  public AuthResponse refresh(String refreshTokenStr, String clientIp) {

    // Step 1: Find token in DB
    RefreshToken storedToken = refreshTokenRepository.findByRefreshToken(refreshTokenStr)
      .orElseThrow(() -> {
        log.warn("Refresh attempt with unknown token from IP: {}", clientIp);
        return new UnauthorizedException("Invalid refresh token");
      });

    // Step 2: Check if revoked — possible token theft
    if (storedToken.isRevoked()) {
      // Someone is using a revoked token. This could mean:
      // - The real user already refreshed (normal token rotation)
      // - An attacker stole the old token and is trying to use it
      // Safety: revoke ALL tokens for this owner to force re-login everywhere
      log.warn("Revoked refresh token used — possible theft. owner_id={}, owner_type={}, ip={}",
        storedToken.getOwnerId(), storedToken.getOwnerType(), clientIp);
      refreshTokenRepository.revokeAllByOwner(storedToken.getOwnerId(), storedToken.getOwnerType());
      throw new UnauthorizedException("Session expired. Please login again.");
    }

    // Step 3: Check if expired
    if (storedToken.getExpiresAt().isBefore(Instant.now())) {
      storedToken.setRevoked(true);
      refreshTokenRepository.save(storedToken);
      log.info("Expired refresh token used. owner_id={}", storedToken.getOwnerId());
      throw new UnauthorizedException("Session expired. Please login again.");
    }

    // Step 4: Check owner type
    if (!"admin".equals(storedToken.getOwnerType())) {
      throw new UnauthorizedException("Invalid token type");
    }

    // Step 4.5: Verify the refresh token JWT belongs to this owner
    // The refresh token is a JWT with sub = admin ID
    // This prevents someone using another admin's refresh token
    Long tokenOwnerId = jwtUtil.extractId(refreshTokenStr);
    if (!tokenOwnerId.equals(storedToken.getOwnerId())) {
      log.warn("Refresh token owner mismatch: jwt_sub={}, db_owner={}",
        tokenOwnerId, storedToken.getOwnerId());
      throw new UnauthorizedException("Invalid refresh token");
    }

    // Step 5: Find admin — get CURRENT state from DB
    Admin admin = adminRepository.findById(storedToken.getOwnerId())
      .orElseThrow(() -> {
        log.error("Refresh token owner not found: admin_id={}", storedToken.getOwnerId());
        return new UnauthorizedException("Account not found");
      });

    // Check if admin is still enabled
    if (!admin.isEnabled()) {
      // Admin was disabled after their last login — kill all sessions
      refreshTokenRepository.revokeAllByOwner(admin.getAdminId(), "admin");
      log.warn("Disabled admin attempted refresh: {}", admin.getEmail());
      throw new ForbiddenException("Your account has been disabled");
    }

    // Step 6: Revoke the old refresh token (rotation)
    storedToken.setRevoked(true);
    refreshTokenRepository.save(storedToken);

    // Step 7: Generate new tokens with CURRENT role
    String newAccessToken = jwtUtil.generateAccessToken(
      admin.getAdminId(),
      admin.getEmail(),
      admin.getRole().name(),
      "admin"
    );

    String newRefreshToken = jwtUtil.generateRefreshToken(
      admin.getAdminId(),
      "admin"
    );

    // Step 8: Save new refresh token
    RefreshToken newTokenEntity = RefreshToken.builder()
      .refreshToken(newRefreshToken)
      .ownerId(admin.getAdminId())
      .ownerType("admin")
      .ipAddress(clientIp)
      .expiresAt(Instant.now().plusMillis(refreshTokenExpiry))
      .build();

    refreshTokenRepository.save(newTokenEntity);
    log.info("Token refreshed for admin: id={}, ip={}", admin.getAdminId(), clientIp);

    return AuthResponse.builder()
      .accessToken(newAccessToken)
      .refreshToken(newRefreshToken)
      .tokenType("Bearer")
      .expiresIn(accessTokenExpiry)
      .profile(adminMapper.toProfileResponse(admin))
      .build();
  }

  /**
   * Logout — revoke the refresh token.
   *
   * After this, the refresh token is dead. The access token
   * still works for up to 15 min (stateless, can't revoke).
   * If you need instant access token revocation, we'd add
   * it to the Redis blacklist here.
   */
  @Override
  @Transactional
  public void logout(String refreshTokenStr, Long adminId) {

    RefreshToken storedToken = refreshTokenRepository.findByRefreshToken(refreshTokenStr)
      .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

    // Verify this token belongs to the requesting admin
    if (!storedToken.getOwnerId().equals(adminId) || !"admin".equals(storedToken.getOwnerType())) {
      log.warn("Logout attempt with another admin's token: requester={}, token_owner={}",
        adminId, storedToken.getOwnerId());
      throw new ForbiddenException("This token does not belong to you");
    }

    if (!storedToken.isRevoked()) {
      storedToken.setRevoked(true);
      refreshTokenRepository.save(storedToken);
      log.info("Admin logged out: admin_id={}", adminId);
    }
  }
}
