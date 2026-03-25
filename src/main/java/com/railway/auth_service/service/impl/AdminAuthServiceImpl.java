package com.railway.auth_service.service.impl;

import com.railway.auth_service.dto.response.AuthResponse;
import com.railway.auth_service.mapper.AdminMapper;
import com.railway.auth_service.model.entity.Admin;
import com.railway.auth_service.repository.AdminRepository;
import com.railway.auth_service.service.AdminAuthService;
import com.railway.auth_service.service.GoogleTokenVerifier;
import com.railway.auth_service.service.GoogleTokenVerifier.GoogleUserInfo;
import com.railway.common.exception.ForbiddenException;
import com.railway.common.exception.ResourceNotFoundException;
import com.railway.common.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Implementation of admin authentication.
 *
 * WHY @Service on impl (not on interface)?
 *   Spring needs to know which class to instantiate.
 *   The interface is a contract — it has no logic, no bean.
 *   The impl has the logic and becomes the Spring bean.
 *   When controller asks for AdminAuthService, Spring injects this.
 *
 * WHY @Transactional?
 *   googleLogin() modifies the admin record (googleId, lastLoginAt,
 *   profileImageUrl, etc.). If the JWT generation fails after the
 *   DB update, the transaction rolls back — no partial state.
 *
 * FLOW:
 *   1. Verify Google token → get GoogleUserInfo
 *   2. Find admin by email → must exist (no self-registration)
 *   3. Check if admin is enabled
 *   4. First login? → store googleId, set emailVerified=true
 *   5. Subsequent login? → verify googleId matches
 *   6. Update lastLoginAt, lastLoginIp, profileImageUrl
 *   7. Generate our JWT tokens
 *   8. Build and return AuthResponse
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminAuthServiceImpl implements AdminAuthService {

  private final GoogleTokenVerifier googleTokenVerifier;
  private final AdminRepository adminRepository;
  private final JwtUtil jwtUtil;
  private final AdminMapper adminMapper;

  @Value("${app.jwt.access-token-expiry}")
  private long accessTokenExpiry;

  @Override
  @Transactional
  public AuthResponse googleLogin(String googleIdToken, String clientIp) {

    // Step 1: Verify token with Google
    GoogleUserInfo googleUser = googleTokenVerifier.verify(googleIdToken);
    log.info("Google token verified for email: {}", googleUser.getEmail());

    // Step 2: Find admin by email — must already exist in DB
    Admin admin = adminRepository.findByEmail(googleUser.getEmail())
      .orElseThrow(() -> {
        log.warn("Admin login rejected — not found: {}", googleUser.getEmail());
        return new ResourceNotFoundException(
          "Admin", "email", googleUser.getEmail()
        );
      });

    // Step 3: Check if account is enabled
    if (!admin.isEnabled()) {
      log.warn("Admin login rejected — disabled: {}", admin.getEmail());
      throw new ForbiddenException("Your account has been disabled");
    }

    // Step 4: First login — store googleId, verify email
    if (admin.getGoogleId() == null) {
      admin.setGoogleId(googleUser.getGoogleId());
      admin.setEmailVerified(true);
      log.info("First Google login — googleId linked for admin: {}", admin.getAdminId());
    }

    // Step 5: Subsequent login — verify googleId matches
    if (!admin.getGoogleId().equals(googleUser.getGoogleId())) {
      log.warn("GoogleId mismatch for admin: {} — possible account takeover attempt",
        admin.getEmail());
      throw new ForbiddenException("Google account mismatch. Contact super admin.");
    }

    // Step 6: Update login metadata
    boolean isFirstLogin = admin.getLastLoginAt() == null;
    admin.setLastLoginAt(Instant.now());
    admin.setLastLoginIp(clientIp);
    admin.setProfileImageUrl(googleUser.getProfileImageUrl());
    // Update name from Google only on first login
    if (isFirstLogin) {
      if (googleUser.getFirstName() != null) admin.setFirstName(googleUser.getFirstName());
      if (googleUser.getLastName() != null) admin.setLastName(googleUser.getLastName());
    }

    adminRepository.save(admin);
    log.info("Admin logged in: id={}, email={}, ip={}", admin.getAdminId(), admin.getEmail(), clientIp);

    // Step 7: Generate our JWT tokens
    String accessToken = jwtUtil.generateAccessToken(
      admin.getAdminId(),
      admin.getEmail(),
      admin.getRole().name(),     // "SUPER_ADMIN" or "ADMIN"
      "admin"                      // type claim
    );

    String refreshToken = jwtUtil.generateRefreshToken(
      admin.getAdminId(),
      "admin"
    );

    // Step 8: Build response
    return AuthResponse.builder()
      .accessToken(accessToken)
      .refreshToken(refreshToken)
      .tokenType("Bearer")
      .expiresIn(accessTokenExpiry)
      .profile(adminMapper.toProfileResponse(admin))
      .build();
  }
}
