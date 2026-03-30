package com.railway.auth_service.service.impl;

import com.railway.auth_service.config.properties.OtpProperties;
import com.railway.auth_service.dto.request.LoginRequest;
import com.railway.auth_service.dto.request.RegisterInitiateRequest;
import com.railway.auth_service.dto.request.RegisterResendRequest;
import com.railway.auth_service.dto.request.RegisterVerifyRequest;
import com.railway.auth_service.dto.response.AuthResponse;
import com.railway.auth_service.dto.response.RegisterInitiateResponse;
import com.railway.auth_service.dto.response.UserProfileResponse;
import com.railway.auth_service.model.entity.RefreshToken;
import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.enums.UserStatus;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.auth_service.service.UserAuthService;
import com.railway.auth_service.service.login.LoginAttemptService;
import com.railway.auth_service.service.otp.OtpService;
import com.railway.common.exception.ConflictException;
import com.railway.common.exception.ForbiddenException;
import com.railway.common.exception.ServiceException;
import com.railway.common.exception.TooManyRequestsException;
import com.railway.common.exception.UnauthorizedException;
import com.railway.common.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Handles user registration flow: initiate → verify → resend.
 * Login methods will be added later.
 *
 * Dependencies follow Dependency Inversion:
 *   - OtpService (not Redis directly — OTP lifecycle is abstracted)
 *   - UserRepository (not EntityManager — data access is abstracted)
 *   - JwtUtil (not JJWT library — token creation is abstracted)
 *   - PasswordEncoder (not BCrypt directly — hashing is abstracted)
 *
 * Each dependency does ONE thing. This class orchestrates them.
 * Single Responsibility: registration flow coordination.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserAuthServiceImpl implements UserAuthService {

  private final UserRepository userRepository;
  private final OtpService otpService;
  private final OtpProperties otpProperties;
  private final PasswordEncoder passwordEncoder;
  private final JwtUtil jwtUtil;
  private final RefreshTokenRepository refreshTokenRepository;
  private final LoginAttemptService loginAttemptService;

  @Value("${app.jwt.access-token-expiry}")
  private long accessTokenExpiry;

  @Value("${app.jwt.refresh-token-expiry}")
  private long refreshTokenExpiry;


  // ═══════════════════════════════════════════
  //  1. INITIATE REGISTRATION
  // ═══════════════════════════════════════════

  @Override
  public RegisterInitiateResponse initiateRegistration(RegisterInitiateRequest request) {

    // ── Step 1: Normalize input ──
    // Why normalize before uniqueness check?
    // "Mehul@Gmail.COM" and "mehul@gmail.com" are the same email.
    // Without normalization, both pass the uniqueness check → duplicate accounts.
    String email = request.getEmail().trim().toLowerCase();
    String username = request.getUsername().trim().toLowerCase();
    String phone = request.getPhone().trim();
    String fullPhone = formatIndianPhone(phone);

    otpService.checkNotAlreadySent(phone);


    // ── Step 2: Check uniqueness ──
    // Why check all three separately instead of one query?
    // To give specific error: "Username taken" vs "Email registered" vs "Phone registered".
    // User knows exactly which field to change. Better UX.
    //
    // Why check DB here when we're not creating the user yet?
    // Fail fast. Don't send OTP and make user wait 5 min only to fail
    // at verify step with "email already exists." Waste of time and SMS credits.
    if (userRepository.existsByUsername(username)) {
      throw new ConflictException("Username '" + username + "' is already taken");
    }
    if (userRepository.existsByEmail(email)) {
      throw new ConflictException("Email '" + email + "' is already registered");
    }
    if (userRepository.existsByPhone(phone)) {
      throw new ConflictException("Phone number is already registered");
    }

    // ── Step 3: Hash password ──
    // Why hash here and not at verify step?
    // We store the hash in Redis. If we hash at verify step,
    // user must send password again → mismatch risk, security risk.
    // Hash once, store in Redis for 5 min, use at verify step.
    String passwordHash = passwordEncoder.encode(request.getPassword());

    // ── Step 4: Build registration data map ──
    // Why HashMap and not Map.of()?
    // Map.of() returns an immutable map. OtpService adds "otp" and
    // "attempts" fields to this map. It needs to be mutable.
    //
    // Why put normalized values, not raw request values?
    // At verify step, we read from Redis and create the user.
    // If we store raw "Mehul@Gmail.COM", user gets created with
    // unnormalized email. Always store the clean version.
    Map<String, String> registrationData = new HashMap<>();
    registrationData.put("username", username);
    registrationData.put("fullName", request.getFullName().trim());
    registrationData.put("email", email);
    registrationData.put("phone", phone);  // 10-digit for DB (phone column is length=10)
    registrationData.put("passwordHash", passwordHash);

    // ── Step 5: Generate OTP, store in Redis, send SMS ──
    // OtpService handles everything: generate → store → send.
    // Returns expiry time in seconds for frontend countdown.
    int expirySeconds = otpService.generateAndStore(fullPhone, registrationData);

    log.info("Registration initiated for username: {}, phone: {}",
      username, maskPhone(phone));

    // ── Step 6: Build response ──
    // Everything is backend-driven. Frontend reads these values
    // and renders accordingly (countdown timer, OTP input boxes).
    String maskedPhone = maskPhone(fullPhone);
    return RegisterInitiateResponse.builder()
      .message("OTP sent to " + maskedPhone)
      .expiresInSeconds(expirySeconds)
      .otpLength(otpProperties.getLength())
      .build();
  }


  // ═══════════════════════════════════════════
  //  2. VERIFY REGISTRATION
  // ═══════════════════════════════════════════

  @Override
  @Transactional
  public AuthResponse verifyRegistration(RegisterVerifyRequest request, String clientIp) {

    // ── Step 1: Verify OTP and get stored data ──
    // OtpService handles: fetch from Redis → check attempts → compare OTP.
    // Returns the registration data map if OTP is correct.
    // Throws BadRequestException or TooManyRequestsException if not.
    Map<String, String> data = otpService.verifyAndGetData(
      formatIndianPhone(request.getPhone()), request.getOtp().trim()
    );

    // ── Step 2: Build User entity ──
    // Why set phoneVerified=true?
    // User just verified their phone via OTP. That's the whole point
    // of the initiate→verify flow.
    //
    // Why NOT set emailVerified=true?
    // Email was never verified. User can verify email later
    // via a separate email OTP flow.
    User user = User.builder()
      .username(data.get("username"))
      .fullName(data.get("fullName"))
      .email(data.get("email"))
      .phone(request.getPhone())
      .passwordHash(data.get("passwordHash"))
      .phoneVerified(true)
      .emailVerified(false)
      .status(UserStatus.ACTIVE)
      .lastLoginAt(Instant.now())
      .lastLoginIp(clientIp)
      .build();

    // ── Step 3: Save user to DB ──
    // Why try-catch DataIntegrityViolationException?
    // Race condition: two users register with same email simultaneously.
    // Both pass uniqueness check at initiate (neither exists in DB yet).
    // Both get OTPs. First one verifies → user created.
    // Second one verifies → DB unique constraint throws.
    // We catch it → "already registered" error.
    //
    // This is the LAST line of defense. The initiate uniqueness check
    // catches 99.9% of cases. This catches the 0.1% race condition.
    try {
      user = userRepository.save(user);
    } catch (DataIntegrityViolationException ex) {
      log.warn("Registration race condition — duplicate data: {}", ex.getMessage());
      throw new ConflictException("An account with this username, email, or phone already exists");
    }

    log.info("User registered: id={}, username={}, phone={}",
      user.getUserId(), user.getUsername(), maskPhone(user.getPhone()));

    // ── Step 4: Generate JWT tokens ──
    // Role is "USER" for all users. Type is "user" (not "admin").
    // JwtUtil is the same one admin auth uses — shared from common lib.
    String accessToken = jwtUtil.generateAccessToken(
      user.getUserId(),
      user.getEmail(),
      "USER",
      "user"
    );

    String refreshToken = jwtUtil.generateRefreshToken(
      user.getUserId(),
      "user"
    );

    // ── Step 5: Save refresh token in DB ──
    // Same pattern as admin auth. ownerType="user" distinguishes
    // from admin refresh tokens in the same table.
    RefreshToken refreshTokenEntity = RefreshToken.builder()
      .refreshToken(refreshToken)
      .ownerId(user.getUserId())
      .ownerType("user")
      .ipAddress(clientIp)
      .expiresAt(Instant.now().plusMillis(refreshTokenExpiry))
      .build();

    refreshTokenRepository.save(refreshTokenEntity);

    // ── Step 6: Build response ──
    UserProfileResponse profile = UserProfileResponse.builder()
      .userId(user.getUserId())
      .username(user.getUsername())
      .fullName(user.getFullName())
      .email(user.getEmail())
      .countryCode(user.getCountryCode())
      .phone(user.getPhone())
      .phoneVerified(user.isPhoneVerified())
      .emailVerified(user.isEmailVerified())
      .profileImageUrl(user.getProfileImageUrl())
      .build();

    return AuthResponse.builder()
      .accessToken(accessToken)
      .refreshToken(refreshToken)
      .tokenType("Bearer")
      .expiresIn(accessTokenExpiry)
      .profile(profile)
      .build();
  }


  // ═══════════════════════════════════════════
  //  3. RESEND OTP
  // ═══════════════════════════════════════════

  @Override
  public RegisterInitiateResponse resendOtp(RegisterResendRequest request) {

    // OtpService handles everything: fetch existing data → new OTP → fresh TTL → send SMS.
    // Throws BadRequestException if no pending registration found.
    String phone = formatIndianPhone(request.getPhone());
    int expirySeconds = otpService.resend(phone);

    log.info("OTP resent for phone: {}", maskPhone(phone));

    return RegisterInitiateResponse.builder()
      .message("OTP resent successfully")
      .expiresInSeconds(expirySeconds)
      .otpLength(otpProperties.getLength())
      .build();
  }

  @Override
  @Transactional
  public AuthResponse login(LoginRequest request, String clientIp) {
    String identifier = request.getIdentifier().trim().toLowerCase();

    User user = findUserByIdentifier(identifier);

    if (user.getStatus() != UserStatus.ACTIVE) {
      String message = switch (user.getStatus()) {
        case LOCKED -> "Your account is locked. " +
          (user.getStatusReason() != null ? user.getStatusReason() : "Contact support.");
        case DISABLED -> "Your account has been disabled";
        case SUSPENDED -> "Your account is under review";
        default -> throw new IllegalStateException("Unexpected value: " + user.getStatus());
      };

      throw new ForbiddenException(message);
    }

    if (loginAttemptService.isLocked(user.getUserId())) {
      long remaining = loginAttemptService.getRemainingLockTime(user.getUserId());
      throw new TooManyRequestsException(
        "Too many failed attempts. Try again in " + remaining + " seconds."
      );
    }

    if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
      loginAttemptService.recordFailedAttempt(user.getUserId());
      // Generic message — don't reveal whether identifier or password is wrong
      throw new UnauthorizedException("Invalid credentials");
    }

    loginAttemptService.resetAttempts(user.getUserId());

    refreshTokenRepository.revokeAllByOwner(user.getUserId(), "user");

    user.setLastLoginAt(Instant.now());
    user.setLastLoginIp(clientIp);
    userRepository.save(user);

    String accessToken = jwtUtil.generateAccessToken(
      user.getUserId(),
      user.getEmail(),
      "USER",
      "user"
    );

    String refreshToken = jwtUtil.generateRefreshToken(
      user.getUserId(),
      "user"
    );

    RefreshToken refreshTokenEntity = RefreshToken.builder()
      .refreshToken(refreshToken)
      .ownerId(user.getUserId())
      .ownerType("user")
      .ipAddress(clientIp)
      .expiresAt(Instant.now().plusMillis(refreshTokenExpiry))
      .build();

    refreshTokenRepository.save(refreshTokenEntity);

    log.info("User logged in: id={}, identifier={}, ip={}",
      user.getUserId(), maskIdentifier(identifier), clientIp);

    UserProfileResponse profile = buildUserProfile(user);

    return AuthResponse.builder()
      .accessToken(accessToken)
      .refreshToken(refreshToken)
      .tokenType("Bearer")
      .expiresIn(accessTokenExpiry)
      .profile(profile)
      .build();

  }

  @Override
  @Transactional
  public AuthResponse refresh(String refreshTokenStr, String clientIp) {
    RefreshToken storedToken = refreshTokenRepository.findByRefreshToken(refreshTokenStr)
      .orElseThrow(() -> {
        log.warn("User refresh attempt with unknown token from IP: {}", clientIp);
        return new UnauthorizedException("Invalid refresh token");
      });

    if (storedToken.isRevoked()) {
      log.warn("Revoked refresh token used — possible theft. owner_id={}, ip={}",
        storedToken.getOwnerId(), clientIp);
      refreshTokenRepository.revokeAllByOwner(storedToken.getOwnerId(), "user");
      throw new UnauthorizedException("Session expired. Please login again.");
    }

    if (storedToken.getExpiresAt().isBefore(Instant.now())) {
      storedToken.setRevoked(true);
      refreshTokenRepository.save(storedToken);
      log.info("Expired refresh token used. owner_id={}", storedToken.getOwnerId());
      throw new UnauthorizedException("Session expired. Please login again.");
    }
    if (!"user".equals(storedToken.getOwnerType())) {
      throw new UnauthorizedException("Invalid token type");
    }

    Long tokenOwnerId = jwtUtil.extractId(refreshTokenStr);
    if (!tokenOwnerId.equals(storedToken.getOwnerId())) {
      log.warn("Refresh token owner mismatch: jwt_sub={}, db_owner={}",
        tokenOwnerId, storedToken.getOwnerId());
      throw new UnauthorizedException("Invalid refresh token");
    }

    User user = userRepository.findById(storedToken.getOwnerId())
      .orElseThrow(() -> {
        log.error("Refresh token owner not found: user_id={}", storedToken.getOwnerId());
        return new UnauthorizedException("Account not found");
      });

    if (user.getStatus() != UserStatus.ACTIVE) {
      refreshTokenRepository.revokeAllByOwner(user.getUserId(), "user");
      log.warn("Non-active user attempted refresh: userId={}, status={}",
        user.getUserId(), user.getStatus());
      throw new ForbiddenException("Your account is not active. Status: " + user.getStatus());
    }

    storedToken.setRevoked(true);
    refreshTokenRepository.save(storedToken);

    String newAccessToken = jwtUtil.generateAccessToken(
      user.getUserId(),
      user.getEmail(),
      "USER",
      "user"
    );

    String newRefreshToken = jwtUtil.generateRefreshToken(
      user.getUserId(),
      "user"
    );

    RefreshToken newTokenEntity = RefreshToken.builder()
      .refreshToken(newRefreshToken)
      .ownerId(user.getUserId())
      .ownerType("user")
      .ipAddress(clientIp)
      .expiresAt(Instant.now().plusMillis(refreshTokenExpiry))
      .build();

    refreshTokenRepository.save(newTokenEntity);

    log.info("Token refreshed for user: id={}, ip={}", user.getUserId(), clientIp);

    return AuthResponse.builder()
      .accessToken(newAccessToken)
      .refreshToken(newRefreshToken)
      .tokenType("Bearer")
      .expiresIn(accessTokenExpiry)
      .profile(buildUserProfile(user))
      .build();

  }


  // ═══════════════════════════════════════════
  //  PRIVATE HELPERS
  // ═══════════════════════════════════════════

  /**
   * Prepends +91 country code to a 10-digit phone number.
   * "9876543210" → "+919876543210"
   */
  private String formatIndianPhone(String phone) {
    return "+91" + phone.trim();
  }

  /**
   * Masks phone for logging.
   * "9876543210" → "****3210"
   */
  private String maskPhone(String phone) {
    if (phone == null || phone.length() < 4) return "****";
    return "****" + phone.substring(phone.length() - 4);
  }

  private User findUserByIdentifier(String identifier) {
    if (identifier.contains("@")) {
      return userRepository.findByEmail(identifier)
        .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));
    }

    if (identifier.matches("^\\d{10}$")) {
      return userRepository.findByPhone(identifier)
        .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));
    }

    return userRepository.findByUsername(identifier)
      .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));
  }

  private UserProfileResponse buildUserProfile(User user) {
    return UserProfileResponse.builder()
      .userId(user.getUserId())
      .username(user.getUsername())
      .fullName(user.getFullName())
      .email(user.getEmail())
      .countryCode(user.getCountryCode())
      .phone(user.getPhone())
      .phoneVerified(user.isPhoneVerified())
      .emailVerified(user.isEmailVerified())
      .profileImageUrl(user.getProfileImageUrl())
      .build();
  }

  private String maskIdentifier(String identifier) {
    if (identifier == null || identifier.length() < 4) return "****";
    if (identifier.contains("@")) {
      int atIndex = identifier.indexOf("@");
      return identifier.substring(0, Math.min(2, atIndex)) + "****" + identifier.substring(atIndex);
    }
    if (identifier.matches("^\\d{10}$")) {
      return "****" + identifier.substring(6);
    }
    return identifier.substring(0, 2) + "****";
  }

}
