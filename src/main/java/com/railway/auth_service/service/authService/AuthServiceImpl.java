package com.railway.auth_service.service.authService;


import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.railway.auth_service.config.googleOAuthConfig.GoogleOAuthConfig;
import com.railway.auth_service.dto.request.auth.GoogleAuthRequest;
import com.railway.auth_service.dto.request.auth.RefreshTokenRequest;
import com.railway.auth_service.dto.response.auth.GoogleAuthResponse;
import com.railway.auth_service.dto.response.auth.RefreshTokenResponse;
import com.railway.auth_service.entity.AdminEntity;
import com.railway.auth_service.entity.RefreshTokenEntity;
import com.railway.auth_service.entity.UserEntity;
import com.railway.common.enums.Role;
import com.railway.common.exceptions.BaseException;
import com.railway.auth_service.repository.AdminRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.common.security.JwtService;
import com.railway.auth_service.service.refreshTokenService.RefreshTokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

  private final AdminRepository adminRepository;
  private final UserRepository userRepository;
  private final JwtService jwtService;
  private final RefreshTokenService refreshTokenService;
  private final GoogleOAuthConfig googleConfig;

  @Value("${jwt.access-token.expiry-ms}")
  private Long accessTokenExpiryMs;


  @Override
  @Transactional
  public GoogleAuthResponse googleTokenVerify(GoogleAuthRequest request) {
    log.info("Starting Google admin authentication");
    try {
      GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
        new NetHttpTransport(),
        GsonFactory.getDefaultInstance()
      )
        .setAudience(Collections.singletonList(googleConfig.getClientId()))
        .build();

      GoogleIdToken idToken = verifier.verify(request.getGoogleAuthToken());

      if (idToken == null) {
        log.error("Google token verification failed");
        throw new BaseException(
          HttpStatus.FORBIDDEN,
          "INVALID_TOKEN",
          "Invalid Google authentication token"
        );
      }

      GoogleIdToken.Payload payload = idToken.getPayload();
      String googleId = payload.getSubject();
      String email = payload.getEmail();
      String name = (String) payload.get("name");
      String picture = (String) payload.get("picture");

      log.info("Google token verified successfully for email: {}", email);

      AdminEntity admin = adminRepository.findByEmail(email)
        .orElseThrow(() -> {
          log.warn("Admin not found for email: {}", email);
          return new BaseException(
            HttpStatus.NOT_FOUND,
            "ADMIN_NOT_FOUND",
            "You are not authorized to access the admin panel. Please contact the system administrator."
          );
        });

      if (!admin.hasAdminPrivileges()) {
        log.warn("User with email {} attempted admin login but has role: {}", email, admin.getAdminRole());
        throw new BaseException(
          HttpStatus.FORBIDDEN,
          "INSUFFICIENT_PRIVILEGES",
          "Access denied. Admin privileges required."
        );
      }

      if (!admin.getIsActive()) {
        log.warn("Inactive admin account attempted login: {}", email);
        throw new BaseException(
          HttpStatus.FORBIDDEN,
          "ACCOUNT_DEACTIVATED",
          "Your account has been deactivated. Please contact support."
        );
      }

      if (admin.getGoogleId() == null || !admin.getGoogleId().equals(googleId)) {
        admin.setGoogleId(googleId);
      }

      admin.setLastLoginAt(LocalDateTime.now());
      adminRepository.save(admin);

      log.info("Admin login successful for: {}", email);

      String accessToken = jwtService.generateAccessTokenForAdmin(admin.getId(), admin.getEmail(), admin.getAdminRole());
      RefreshTokenEntity refreshToken = refreshTokenService.createRefreshTokenForAdmin(admin.getId());

      return GoogleAuthResponse.builder()
        .accessToken(accessToken)
        .refreshToken(refreshToken.getRefreshToken())
        .expiresIn(accessTokenExpiryMs / 1000)
        .id(admin.getId())
        .email(admin.getEmail())
        .name(name)
        .phoneNumber(admin.getPhoneNumber())
        .countryCode(admin.getCountryCode())
        .profilePicture(picture)
        .isActive(admin.getIsActive())
        .createdAt(admin.getCreatedAt())
        .lastLoginAt(admin.getLastLoginAt())
        .build();

    } catch (BaseException e) {
      throw e;
    } catch (GeneralSecurityException | IOException e) {
      log.error("Google token verification failed: {}", e.getMessage());
      throw new BaseException(
        HttpStatus.FORBIDDEN,
        "INVALID_TOKEN",
        "Invalid or expired Google authentication token"
      );
    } catch (Exception e) {
      log.error("Google admin authentication failed", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "AUTH_ERROR",
        "Authentication failed. Please try again."
      );
    }
  };

  @Override
  @Transactional
  public RefreshTokenResponse refreshAccessToken(RefreshTokenRequest request) {
    log.info("=== Starting Refresh Token Flow ===");

    try {
      // ========== STEP 1: VERIFY REFRESH TOKEN ==========
      log.debug("Step 1: Verifying refresh token from database");

      RefreshTokenEntity refreshToken = refreshTokenService.verifyRefreshToken(
        request.getRefreshToken()
      );

      // This method already checks:
      // - Token exists in DB
      // - Token is not revoked
      // - Token is not expired
      // - JWT signature is valid

      log.info("Refresh token verified for {}: {}",
        refreshToken.getOwnerType(), refreshToken.getOwnerId());

      // ========== STEP 2: EXTRACT OWNER INFO ==========
      log.debug("Step 2: Extracting owner information");

      Long ownerId = refreshToken.getOwnerId();
      Role ownerType = refreshToken.getOwnerType();

      log.debug("Owner ID: {}, Owner Type: {}", ownerId, ownerType);

      // ========== STEP 3: VALIDATE OWNER & GENERATE NEW ACCESS TOKEN ==========
      log.debug("Step 3: Validating owner and generating new access token");

      String newAccessToken;
      RefreshTokenResponse response;

      if (ownerType == Role.USER) {
        // ===== USER FLOW =====
        log.debug("Processing refresh for USER");

        response = handleUserRefresh(ownerId, refreshToken);

      } else {
        // ===== ADMIN FLOW (ADMIN or SUPER_ADMIN) =====
        log.debug("Processing refresh for ADMIN");

        response = handleAdminRefresh(ownerId, ownerType, refreshToken);
      }

      // ========== STEP 4: ROTATE REFRESH TOKEN ==========
      log.debug("Step 4: Rotating refresh token (security best practice)");

      RefreshTokenEntity newRefreshToken = refreshTokenService.rotateRefreshToken(
        request.getRefreshToken()
      );

      // Why rotate?
      // - Prevents token replay attacks
      // - Limits damage if token is stolen
      // - Industry best practice (OAuth 2.0 recommendation)

      response.setRefreshToken(newRefreshToken.getRefreshToken());

      log.info("=== Refresh Token Flow Completed Successfully ===");
      log.info("New tokens generated for {}: {}", ownerType, ownerId);

      return response;

    } catch (BaseException e) {
      log.error("Refresh token flow failed: {}", e.getMessage());
      throw e;
    } catch (Exception e) {
      log.error("Unexpected error during refresh token flow", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "REFRESH_FAILED",
        "Failed to refresh access token. Please try again."
      );
    }
  }

  // ========== PRIVATE HELPER METHODS ==========

  /**
   * Handle refresh token for USER
   *
   * Checks:
   * - User exists
   * - User is active (not deactivated)
   * - User is not blocked
   * - User account is not locked
   */
  private RefreshTokenResponse handleUserRefresh(Long userId, RefreshTokenEntity refreshToken) {
    log.debug("Fetching user from database: {}", userId);

    UserEntity user = userRepository.findById(userId)
      .orElseThrow(() -> {
        log.error("User not found: {}", userId);
        return new BaseException(
          HttpStatus.FORBIDDEN,
          "USER_NOT_FOUND",
          "User account no longer exists"
        );
      });

    // Check if user account is still valid
    if (!user.canLogin()) {
      log.warn("User {} cannot login - account issue", userId);

      if (user.getIsBlocked()) {
        throw new BaseException(
          HttpStatus.FORBIDDEN,
          "ACCOUNT_BLOCKED",
          "Your account has been blocked. Reason: " + user.getBlockedReason()
        );
      }

      if (!user.getIsActive()) {
        throw new BaseException(
          HttpStatus.FORBIDDEN,
          "ACCOUNT_DEACTIVATED",
          "Your account has been deactivated. Please contact support."
        );
      }

      if (user.isAccountLocked()) {
        throw new BaseException(
          HttpStatus.FORBIDDEN,
          "ACCOUNT_LOCKED",
          "Your account is temporarily locked. Please try again later."
        );
      }
    }

    log.debug("User validation passed. Generating new access token.");

    // Generate new access token for USER
    String newAccessToken = jwtService.generateAccessTokenForUser(
      user.getId(),
      user.getEmail()
    );

    // Build response with user-specific data
    return RefreshTokenResponse.builder()
      .accessToken(newAccessToken)
      .expiresIn(accessTokenExpiryMs / 1000)
      .ownerType("USER")
      .ownerId(user.getId())
      .email(user.getEmail())
      // User-specific fields
      .userId(user.getId())
      .userName(user.getUserName())
      // Admin fields will be null (handled by @JsonInclude)
      .build();
  }

  /**
   * Handle refresh token for ADMIN
   *
   * Checks:
   * - Admin exists
   * - Admin is active
   * - Admin role is valid (ADMIN or SUPER_ADMIN)
   */
  private RefreshTokenResponse handleAdminRefresh(
    Long adminId,
    Role adminRole,
    RefreshTokenEntity refreshToken
  ) {
    log.debug("Fetching admin from database: {}", adminId);

    AdminEntity admin = adminRepository.findById(adminId)
      .orElseThrow(() -> {
        log.error("Admin not found: {}", adminId);
        return new BaseException(
          HttpStatus.FORBIDDEN,
          "ADMIN_NOT_FOUND",
          "Admin account no longer exists"
        );
      });

    // Check if admin account is still valid
    if (!admin.canLogin()) {
      log.warn("Admin {} cannot login - account deactivated", adminId);
      throw new BaseException(
        HttpStatus.FORBIDDEN,
        "ACCOUNT_DEACTIVATED",
        "Your admin account has been deactivated. Please contact the system administrator."
      );
    }

    // Verify admin role hasn't changed (security check)
    if (!admin.getAdminRole().equals(adminRole)) {
      log.warn("Admin role mismatch for {}: token={}, db={}",
        adminId, adminRole, admin.getAdminRole());
      throw new BaseException(
        HttpStatus.FORBIDDEN,
        "ROLE_CHANGED",
        "Your admin privileges have changed. Please login again."
      );
    }

    log.debug("Admin validation passed. Generating new access token.");

    // Generate new access token for ADMIN
    String newAccessToken = jwtService.generateAccessTokenForAdmin(
      admin.getId(),
      admin.getEmail(),
      admin.getAdminRole()
    );

    // Build response with admin-specific data
    return RefreshTokenResponse.builder()
      .accessToken(newAccessToken)
      .expiresIn(accessTokenExpiryMs / 1000)
      .ownerType("ADMIN")
      .ownerId(admin.getId())
      .email(admin.getEmail())
      // Admin-specific fields
      .adminId(admin.getId())
      .adminRole(admin.getAdminRole().name())
      .department(admin.getDepartment())
      // User fields will be null (handled by @JsonInclude)
      .build();
  }
}
