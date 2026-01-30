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
import com.railway.auth_service.enums.Role;
import com.railway.auth_service.exception.BaseException;
import com.railway.auth_service.repository.AdminRepository;
import com.railway.auth_service.repository.UserAdminRepository;
import com.railway.auth_service.service.jwtService.JwtService;
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
public class AuthServiceImpl implements AuthService{

  private final UserAdminRepository userAdminRepository;
  private final AdminRepository adminRepository;
  private final JwtService jwtService;
  private final GoogleOAuthConfig googleConfig;
  private final RefreshTokenService refreshTokenService;

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

      String accessToken = jwtService.generateAccessToken(admin.getId(),admin.getEmail(),admin.getAdminRole(), "admin");
      RefreshTokenEntity refreshTokenEntity = refreshTokenService.createRefreshToken(admin.getId(), admin.getAdminRole());

      return GoogleAuthResponse.builder()
        .accessToken(accessToken)
        .refreshToken(refreshTokenEntity.getRefreshToken())
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
  }

  @Override
  @Transactional
  public RefreshTokenResponse refreshAccessToken(RefreshTokenRequest request) {
    log.info("Refreshing access token");

    try {
      // Verify refresh token
      RefreshTokenEntity refreshToken = refreshTokenService.verifyRefreshToken(
        request.getRefreshToken()
      );

      // Get user
      UserEntity user = userAdminRepository.findById(refreshToken.getUserId())
        .orElseThrow(() -> new BaseException(HttpStatus.FORBIDDEN,"USER_NOT_FOUND","No user found"));

      // Check if user is still active
      if (!user.getIsActive()) {
        throw new BaseException( HttpStatus.FORBIDDEN,
          "ACCOUNT_DEACTIVATED",
          "Your account has been deactivated. Please contact support.");
      }

      // Generate new access token
      String newAccessToken = jwtService.generateAccessToken(user);

      // Rotate refresh token (best practice)
      RefreshTokenEntity newRefreshToken = refreshTokenService.rotateRefreshToken(
        request.getRefreshToken()
      );

      log.info("Access token refreshed for user: {}", user.getEmail());

      // Build response
      return RefreshTokenResponse.builder()
        .accessToken(newAccessToken)
        .refreshToken(newRefreshToken.getToken())
        .userId(user.getId())
        .email(user.getEmail())
        .build();

    } catch (BaseException e) {
      log.error("Failed to refresh access token", e);
      throw e;
    }
  }
}
