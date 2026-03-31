package com.railway.auth_service.service.otp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.railway.auth_service.config.properties.OtpProperties;
import com.railway.auth_service.service.email.EmailService;
import com.railway.auth_service.service.sms.SmsService;
import com.railway.common.exception.BadRequestException;
import com.railway.common.exception.TooManyRequestsException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Manages OTP lifecycle: generate, store, verify, resend.
 *
 * Responsibilities:
 *   - Generate OTP (fixed or random based on config)
 *   - Store registration data + OTP in Redis with TTL
 *   - Verify OTP and return stored registration data
 *   - Resend OTP with fresh TTL
 *
 * Does NOT:
 *   - Create users in DB (UserAuthService does that)
 *   - Hash passwords (UserAuthService does that)
 *   - Validate registration fields (UserAuthService does that)
 *
 * Single Responsibility: only OTP lifecycle, nothing else.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

  /**
   * Redis key prefix for registration OTPs.
   * Full key: "auth:register:otp:{phone}"
   *
   * Namespaced so it doesn't collide with future OTP types:
   *   "auth:login:otp:{phone}"       (login OTP — future)
   *   "auth:reset:otp:{phone}"       (password reset — future)
   *   "auth:email:otp:{email}"       (email verification — future)
   */
  private static final String OTP_KEY_PREFIX = "auth:register:otp:";
  private static final String COOLDOWN_KEY_PREFIX = "auth:register:cooldown:";

  private static final String EMAIL_OTP_KEY_PREFIX = "auth:email:otp:";
  private static final String EMAIL_COOLDOWN_KEY_PREFIX = "auth:email:cooldown:";
  private static final String FIELD_USER_ID = "userId";

  /**
   * Keys used internally in the Redis map.
   * Constants avoid typos — "otp" vs "Otp" vs "OTP" bugs.
   */
  private static final String FIELD_OTP = "otp";
  private static final String FIELD_ATTEMPTS = "attempts";
  private final SmsService smsService;
  private final StringRedisTemplate redisTemplate;
  private final ObjectMapper objectMapper;
  private final OtpProperties otpProperties;
  private final EmailService emailService;

  /**
   * SecureRandom created once, reused for all OTP generations.
   *
   * Why not inject via constructor?
   * It's not a Spring bean — it's a utility. No reason to manage
   * its lifecycle through Spring. Simple field initialization.
   *
   * Why final?
   * Immutable reference. Thread-safe for concurrent OTP generation.
   */
  private final SecureRandom secureRandom = new SecureRandom();

  /**
   * TypeReference for deserializing JSON back to Map.
   * Created once — no need to create a new instance every time.
   */
  private static final TypeReference<Map<String, String>> MAP_TYPE = new TypeReference<>() {};


  // ═══════════════════════════════════════════
  //  1. GENERATE AND STORE
  // ═══════════════════════════════════════════

  /**
   * Generates OTP, stores registration data in Redis, sends SMS.
   *
   * @param phone            10-digit phone number (without country code)
   * @param registrationData user data to store temporarily (username, fullName, email, etc.)
   * @return OTP expiry time in seconds (for frontend countdown)
   *
   * @throws BadRequestException      if OTP already sent for this phone
   * @throws IllegalStateException    if JSON serialization fails
   */
  public int generateAndStore(String phone, Map<String, String> registrationData) {

    String redisCoolDownKey = COOLDOWN_KEY_PREFIX + phone;
    if (redisTemplate.hasKey(redisCoolDownKey)) {
      Long remainingSeconds = redisTemplate.getExpire(redisCoolDownKey, TimeUnit.SECONDS);
      throw new TooManyRequestsException(
        "Too many failed attempts. Try again in " + remainingSeconds + " seconds."
      );
    }


    String redisKey = OTP_KEY_PREFIX + phone;

    /*
     * Check if OTP already exists for this phone.
     *
     * Why check before generating?
     * Without this, user spams Register button →
     *   → each click generates new OTP, sends new SMS
     *   → burns SMS credits, overwrites previous OTP
     *   → user gets confused (which OTP is valid?)
     *
     * With this check:
     *   → first click: OTP sent
     *   → second click: "OTP already sent, wait"
     *   → user waits or clicks Resend (controlled flow)
     */
    if (Boolean.TRUE.equals(redisTemplate.hasKey(redisKey))) {
      throw new BadRequestException("OTP already sent to this number. Please wait or use resend.");
    }

    // Generate OTP — fixed (dev) or random (prod)
    String otp = generateOtp();

    /*
     * Send SMS BEFORE storing in Redis.
     *
     * Why send first?
     * If SMS fails (network error, Twilio down, invalid number),
     * no Redis entry is created → user can retry immediately.
     * If we stored in Redis first and SMS failed, user gets
     * "OTP already sent" on retry but never received the OTP.
     *
     * phone already contains country code (e.g. "+919876543210")
     * passed by caller via formatIndianPhone().
     */
    smsService.sendOtp(phone, otp);

    /*
     * SMS sent successfully — now store in Redis.
     *
     * Add OTP and attempts counter to the registration data map.
     * StringRedisTemplate stores everything as strings.
     * Map<String, String> keeps it consistent. We parse to int when needed.
     */
    registrationData.put(FIELD_OTP, otp);
    registrationData.put(FIELD_ATTEMPTS, "0");

    String jsonValue = serialize(registrationData);
    redisTemplate.opsForValue().set(redisKey, jsonValue, otpProperties.getExpirySeconds(), TimeUnit.SECONDS);

    log.info("OTP generated and stored for phone: {}", maskPhone(phone));

    return otpProperties.getExpirySeconds();
  }


  // ═══════════════════════════════════════════
  //  2. VERIFY AND GET DATA
  // ═══════════════════════════════════════════

  /**
   * Verifies OTP and returns stored registration data.
   *
   * @param phone 10-digit phone number
   * @param otp   OTP entered by user
   * @return registration data (username, fullName, email, etc.) — no OTP or attempts
   *
   * @throws BadRequestException      if OTP expired/not found
   * @throws BadRequestException      if OTP is invalid
   * @throws TooManyRequestsException if max attempts exceeded
   */
  public Map<String, String> verifyAndGetData(String phone, String otp) {

    String redisKey = OTP_KEY_PREFIX + phone;

    /*
     * Fetch stored data from Redis.
     *
     * Returns null if:
     *   - Key never existed (user didn't initiate registration)
     *   - Key expired (TTL passed — OTP expired)
     *   - Key was deleted (max attempts exceeded in previous call)
     *
     * All three cases → same response. Don't reveal which one.
     * "OTP expired" is vague enough — doesn't leak info.
     */
    String jsonValue = redisTemplate.opsForValue().get(redisKey);

    if (jsonValue == null) {
      throw new BadRequestException("OTP expired or not found. Please register again.");
    }

    Map<String, String> storedData = deserialize(jsonValue);
    int attempts = Integer.parseInt(storedData.get(FIELD_ATTEMPTS));

    /*
     * Check if max attempts exceeded.
     *
     * Why check BEFORE comparing OTP?
     * If we compare first, attacker gets one extra attempt on each call.
     * Check count first → if already at limit, reject immediately.
     *
     * Why delete the Redis key?
     * Attacker can't keep calling verify after hitting the limit.
     * Key is gone → next call gets "OTP expired" → must restart.
     */
    if (attempts >= otpProperties.getMaxAttempts()) {

      String cooldownKey = COOLDOWN_KEY_PREFIX + phone;
      redisTemplate.opsForValue().set(
        cooldownKey, "1", otpProperties.getCooldownSeconds(), TimeUnit.SECONDS
      );

      redisTemplate.delete(redisKey);
      log.warn("Max OTP attempts exceeded for phone: {}", maskPhone(phone));
      throw new TooManyRequestsException("Too many failed attempts. Please register again.");
    }

    // Compare OTPs
    String storedOtp = storedData.get(FIELD_OTP);

    if (!storedOtp.equals(otp)) {
      /*
       * Wrong OTP — increment attempts and update Redis.
       *
       * Why use getExpire() to preserve remaining TTL?
       * If original TTL was 300s and 120s have passed, remaining = 180s.
       * We store with 180s TTL — not a fresh 300s.
       *
       * Why? If we reset to 300s on every wrong attempt:
       *   → attacker enters wrong OTP → TTL resets to 5 min
       *   → attacker waits 4 min → enters wrong OTP → TTL resets again
       *   → attacker has unlimited time to guess
       *
       * With remaining TTL:
       *   → original 5 min window keeps shrinking
       *   → after 5 min, key expires regardless of attempts
       */
      attempts++;
      storedData.put(FIELD_ATTEMPTS, String.valueOf(attempts));

      Long remainingTtl = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
      if (remainingTtl != null && remainingTtl > 0) {
        redisTemplate.opsForValue().set(redisKey, serialize(storedData), remainingTtl, TimeUnit.SECONDS);
      }

      int remaining = otpProperties.getMaxAttempts() - attempts;
      log.warn("Invalid OTP attempt for phone: {}. {} attempts remaining", maskPhone(phone), remaining);
      throw new BadRequestException("Invalid OTP. " + remaining + " attempt(s) remaining.");
    }

    /*
     * OTP is correct!
     *
     * Delete Redis key — OTP is used, one-time only.
     * If we don't delete, someone who intercepted the OTP
     * could replay it within the TTL window.
     */
    redisTemplate.delete(redisKey);

    /*
     * Remove internal fields before returning.
     * Caller (UserAuthService) gets only registration data:
     * { username, fullName, email, countryCode, phone }
     *
     * No OTP, no attempts — those are OTP internals.
     * Don't leak implementation details to callers.
     */
    storedData.remove(FIELD_OTP);
    storedData.remove(FIELD_ATTEMPTS);

    log.info("OTP verified successfully for phone: {}", maskPhone(phone));

    return storedData;
  }


  // ═══════════════════════════════════════════
  //  3. RESEND
  // ═══════════════════════════════════════════

  /**
   * Resends OTP with a new value and fresh TTL.
   *
   * @param phone 10-digit phone number
   * @return OTP expiry time in seconds
   *
   * @throws BadRequestException if no pending registration found
   */
  public int resend(String phone) {

    String redisKey = OTP_KEY_PREFIX + phone;

    /*
     * Fetch existing data.
     *
     * Why must it exist?
     * Resend only works if registration was initiated.
     * If key expired, the registration data (username, email, etc.) is gone.
     * User must fill the form and initiate again.
     */
    String jsonValue = redisTemplate.opsForValue().get(redisKey);

    if (jsonValue == null) {
      throw new BadRequestException("No pending registration found. Please register again.");
    }

    Map<String, String> storedData = deserialize(jsonValue);

    // Generate new OTP — old one is now invalid (overwritten)
    String newOtp = generateOtp();

    // Send SMS BEFORE updating Redis.
    // If SMS fails, old OTP remains valid in Redis — user can retry resend.
    smsService.sendOtp(phone, newOtp);

    /*
     * SMS sent successfully — now update Redis.
     *
     * Reset attempts to 0: new OTP = fresh start.
     * Fresh TTL: user explicitly asked for a new OTP,
     * fair to give them a full window.
     */
    storedData.put(FIELD_OTP, newOtp);
    storedData.put(FIELD_ATTEMPTS, "0");

    redisTemplate.opsForValue().set(redisKey, serialize(storedData), otpProperties.getExpirySeconds(), TimeUnit.SECONDS);

    log.info("OTP resent for phone: {}", maskPhone(phone));

    return otpProperties.getExpirySeconds();
  }

  public void checkNotAlreadySent(String phone) {
    String redisKey = OTP_KEY_PREFIX + phone;
    if (redisTemplate.hasKey(redisKey)) {
      throw new BadRequestException("OTP already sent to this number. Please wait or use resend.");
    }
  }


  // ═══════════════════════════════════════════
//  EMAIL OTP: GENERATE AND SEND
// ═══════════════════════════════════════════

  /**
   * Generates OTP for email verification and sends it via email.
   *
   * @param email  user's email address
   * @param userId user's DB ID (stored in Redis so verify step knows who to update)
   * @return OTP expiry time in seconds
   *
   * Same logic as registration OTP but:
   *   - Different Redis key prefix (auth:email:otp vs auth:register:otp)
   *   - Stores userId instead of registration data (user already exists)
   *   - Sends via EmailService instead of SmsService
   */
  public int generateAndSendEmailOtp(String email, Long userId) {

    // Check cooldown
    String cooldownKey = EMAIL_COOLDOWN_KEY_PREFIX + email;
    if (redisTemplate.hasKey(cooldownKey)) {
      Long remainingSeconds = redisTemplate.getExpire(cooldownKey, TimeUnit.SECONDS);
      throw new TooManyRequestsException(
        "Too many failed attempts. Try again in " + remainingSeconds + " seconds."
      );
    }

    // Check if OTP already sent
    String redisKey = EMAIL_OTP_KEY_PREFIX + email;
    if (redisTemplate.hasKey(redisKey)) {
      throw new BadRequestException("OTP already sent to this email. Please wait or use resend.");
    }

    String otp = generateOtp();

    // Send email BEFORE storing in Redis.
    // If email fails, no Redis entry → user can retry immediately.
    emailService.sendOtp(email, otp, "Verify your email - Railway Booking");

    // Email sent successfully — now store in Redis
    Map<String, String> data = new HashMap<>();
    data.put(FIELD_OTP, otp);
    data.put(FIELD_ATTEMPTS, "0");
    data.put(FIELD_USER_ID, String.valueOf(userId));

    redisTemplate.opsForValue().set(redisKey, serialize(data), otpProperties.getExpirySeconds(), TimeUnit.SECONDS);

    log.info("Email OTP sent to {}", maskEmail(email));

    return otpProperties.getExpirySeconds();
  }


// ═══════════════════════════════════════════
//  EMAIL OTP: VERIFY
// ═══════════════════════════════════════════

  /**
   * Verifies email OTP and returns the userId.
   *
   * @param email user's email address
   * @param otp   OTP entered by user
   * @return userId of the verified user
   */
  public Long verifyEmailOtp(String email, String otp) {

    String redisKey = EMAIL_OTP_KEY_PREFIX + email;
    String jsonValue = redisTemplate.opsForValue().get(redisKey);

    if (jsonValue == null) {
      throw new BadRequestException("OTP expired or not found. Please request a new one.");
    }

    Map<String, String> storedData = deserialize(jsonValue);
    int attempts = Integer.parseInt(storedData.get(FIELD_ATTEMPTS));

    // Max attempts check
    if (attempts >= otpProperties.getMaxAttempts()) {
      // Set cooldown
      String cooldownKey = EMAIL_COOLDOWN_KEY_PREFIX + email;
      redisTemplate.opsForValue().set(
        cooldownKey, "1", otpProperties.getCooldownSeconds(), TimeUnit.SECONDS
      );
      redisTemplate.delete(redisKey);

      log.warn("Max email OTP attempts exceeded for: {}", maskEmail(email));
      throw new TooManyRequestsException(
        "Too many failed attempts. Try again in " + otpProperties.getCooldownSeconds() + " seconds."
      );
    }

    // Compare OTP
    String storedOtp = storedData.get(FIELD_OTP);

    if (!storedOtp.equals(otp)) {
      attempts++;
      storedData.put(FIELD_ATTEMPTS, String.valueOf(attempts));

      Long remainingTtl = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
      if (remainingTtl != null && remainingTtl > 0) {
        redisTemplate.opsForValue().set(redisKey, serialize(storedData), remainingTtl, TimeUnit.SECONDS);
      }

      int remaining = otpProperties.getMaxAttempts() - attempts;
      log.warn("Invalid email OTP for: {}. {} attempts remaining", maskEmail(email), remaining);
      throw new BadRequestException("Invalid OTP. " + remaining + " attempt(s) remaining.");
    }

    // OTP correct — clean up
    redisTemplate.delete(redisKey);

    Long userId = Long.parseLong(storedData.get(FIELD_USER_ID));
    log.info("Email OTP verified for: {}", maskEmail(email));

    return userId;
  }


// ═══════════════════════════════════════════
//  EMAIL OTP: RESEND
// ═══════════════════════════════════════════

  /**
   * Resends email OTP with new value and fresh TTL.
   *
   * @param email  user's email address
   * @param userId user's DB ID
   * @return OTP expiry time in seconds
   */
  public int resendEmailOtp(String email, Long userId) {

    String redisKey = EMAIL_OTP_KEY_PREFIX + email;
    String jsonValue = redisTemplate.opsForValue().get(redisKey);

    if (jsonValue == null) {
      throw new BadRequestException("No pending email verification. Please request a new OTP.");
    }

    String newOtp = generateOtp();

    // Send email BEFORE updating Redis.
    // If email fails, old OTP remains valid — user can retry resend.
    emailService.sendOtp(email, newOtp, "Verify your email - Railway Booking");

    // Email sent successfully — now update Redis
    Map<String, String> storedData = deserialize(jsonValue);
    storedData.put(FIELD_OTP, newOtp);
    storedData.put(FIELD_ATTEMPTS, "0");

    redisTemplate.opsForValue().set(redisKey, serialize(storedData), otpProperties.getExpirySeconds(), TimeUnit.SECONDS);

    log.info("Email OTP resent to {}", maskEmail(email));

    return otpProperties.getExpirySeconds();
  }

  /**
   * Masks email for logging.
   * "mehul@gmail.com" → "me****@gmail.com"
   */
  private String maskEmail(String email) {
    if (email == null || !email.contains("@")) return "****";
    int atIndex = email.indexOf("@");
    String local = email.substring(0, atIndex);
    String domain = email.substring(atIndex);
    if (local.length() <= 2) return local + "****" + domain;
    return local.substring(0, 2) + "****" + domain;
  }


  // ═══════════════════════════════════════════
  //  PRIVATE HELPERS
  // ═══════════════════════════════════════════

  /**
   * Generates OTP based on config.
   *
   * Dev:  returns fixed value ("111111") — always the same, easy to test.
   * Prod: returns random N-digit number — secure, unpredictable.
   *
   * Why String.format with leading zeros?
   * SecureRandom might generate 4523 for a 6-digit OTP.
   * Without format: "4523" (4 digits — wrong length)
   * With format:    "004523" (6 digits — correct)
   * %06d = pad with zeros to 6 digits.
   *
   * Why calculate bound as (int) Math.pow(10, length)?
   * For length=6: bound = 1000000, range = 0 to 999999.
   * Formatted with %06d → "000000" to "999999". All 6 digits.
   */
  private String generateOtp() {
    if (otpProperties.isUseFixed()) {
      return otpProperties.getFixedValue();
    }

    int bound = (int) Math.pow(10, otpProperties.getLength());
    int randomValue = secureRandom.nextInt(bound);
    return String.format("%0" + otpProperties.getLength() + "d", randomValue);
  }

  /**
   * Serializes Map to JSON string for Redis storage.
   *
   * Why wrap in try-catch and throw IllegalStateException?
   * JsonProcessingException is a checked exception.
   * But serializing a Map<String, String> should NEVER fail —
   * it's simple key-value pairs, no complex objects.
   * If it fails, something is fundamentally wrong — runtime exception.
   * Don't force callers to handle an impossible error.
   */
  private String serialize(Map<String, String> data) {
    try {
      return objectMapper.writeValueAsString(data);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException("Failed to serialize OTP data", e);
    }
  }

  /**
   * Deserializes JSON string from Redis back to Map.
   * Same error handling philosophy as serialize.
   */
  private Map<String, String> deserialize(String json) {
    try {
      return objectMapper.readValue(json, MAP_TYPE);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException("Failed to deserialize OTP data", e);
    }
  }

  /**
   * Masks phone number for logging.
   * "9876543210" → "****3210"
   *
   * Why? Logs shouldn't contain full phone numbers.
   * If logs are leaked, attacker can't extract user phones.
   */
  private String maskPhone(String phone) {
    if (phone == null || phone.length() < 4) return "****";
    return "****" + phone.substring(phone.length() - 4);
  }
}
