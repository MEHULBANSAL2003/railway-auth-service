package com.railway.auth_service.service.login;

import com.railway.auth_service.config.properties.LoginProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Manages brute force protection for user login via Redis.
 *
 * Three operations:
 *   - isLocked: check if user is currently locked out
 *   - recordFailedAttempt: increment counter, lock if threshold reached
 *   - resetAttempts: clear everything on successful login
 *
 * Why a separate service and not inline in UserAuthServiceImpl?
 *   Single Responsibility — login orchestration is one concern,
 *   brute force tracking is another. UserAuthServiceImpl calls
 *   clean methods (isLocked, recordFailedAttempt, resetAttempts)
 *   without knowing about Redis keys, TTLs, or counters.
 *
 * All state is in Redis — no DB fields needed.
 * Redis TTL handles auto-unlock — no cron jobs, no lazy cleanup.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAttemptService {

  /**
   * Redis key prefixes for login tracking.
   *
   * Why "user" in the key?
   * Admins don't use password login (Google OAuth only).
   * But if they ever do, we'd add "auth:login:failed:admin:{id}".
   * Namespacing prevents collision.
   *
   * Why by user ID and not by identifier (email/phone/username)?
   * Same user can login via email, phone, or username.
   * If we track by identifier:
   *   → 4 failed via email + 4 failed via phone = 8 attempts, not locked
   * If we track by user ID:
   *   → 4 + 4 = 8 attempts total → locked after 5th
   * User ID is the correct key for per-account lockout.
   */
  private static final String FAILED_KEY_PREFIX = "auth:login:failed:user:";
  private static final String LOCKED_KEY_PREFIX = "auth:login:locked:user:";

  private final StringRedisTemplate redisTemplate;
  private final LoginProperties loginProperties;

  /**
   * Checks if a user is currently locked out.
   *
   * @param userId the user's DB ID
   * @return true if locked, false if not
   *
   * Called BEFORE password verification.
   * If locked, don't even check the password — reject immediately.
   * Protects DB from unnecessary bcrypt comparisons during attack.
   */
  public boolean isLocked(Long userId) {
    String lockedKey = LOCKED_KEY_PREFIX + userId;
    return redisTemplate.hasKey(lockedKey);
  }

  /**
   * Returns remaining lock time in seconds.
   * Used to tell the user how long to wait.
   *
   * @param userId the user's DB ID
   * @return seconds remaining, or 0 if not locked
   */
  public long getRemainingLockTime(Long userId) {
    String lockedKey = LOCKED_KEY_PREFIX + userId;
    Long ttl = redisTemplate.getExpire(lockedKey, TimeUnit.SECONDS);
    return (ttl != null && ttl > 0) ? ttl : 0;
  }

  /**
   * Records a failed login attempt.
   *
   * Increments the counter. If threshold reached, sets the lock key.
   *
   * @param userId the user's DB ID
   *
   * Why INCR and not GET → increment → SET?
   * Redis INCR is atomic — safe for concurrent requests.
   * If two failed attempts happen at the same millisecond,
   * both correctly increment the counter. No race condition.
   *
   * Why set TTL on the failed counter?
   * Without TTL, a user who fails once per month would eventually
   * accumulate 5 failures and get locked — even though they're not
   * under attack. TTL resets the window. If 30 minutes pass without
   * a failure, counter resets to 0 (key expires).
   */
  public void recordFailedAttempt(Long userId) {
    String failedKey = FAILED_KEY_PREFIX + userId;

    /*
     * INCR returns the new count after incrementing.
     * If key doesn't exist, Redis creates it with value 1.
     * Atomic — no race conditions.
     */
    Long attempts = redisTemplate.opsForValue().increment(failedKey);

    if (attempts == null) {
      return;
    }

    /*
     * Set TTL on first attempt only.
     *
     * Why only on first attempt (attempts == 1)?
     * If we set TTL on every attempt, the window keeps extending.
     * Attacker: fail → TTL 30min → wait 29min → fail → TTL 30min again.
     * With TTL only on first attempt, the 30-minute window is fixed.
     * After 30 min, key expires regardless of subsequent attempts.
     *
     * Same logic we used in OTP verify — don't reward attackers
     * with more time.
     */
    if (attempts == 1) {
      redisTemplate.expire(failedKey, loginProperties.getLockDurationSeconds(), TimeUnit.SECONDS);
    }

    /*
     * Check if threshold reached.
     */
    if (attempts >= loginProperties.getMaxAttempts()) {
      String lockedKey = LOCKED_KEY_PREFIX + userId;
      redisTemplate.opsForValue().set(
        lockedKey, "1",
        loginProperties.getLockDurationSeconds(), TimeUnit.SECONDS
      );

      // Delete the failed counter — no longer needed, user is locked
      redisTemplate.delete(failedKey);

      log.warn("User locked after {} failed attempts: userId={}", attempts, userId);
    } else {
      int remaining = loginProperties.getMaxAttempts() - attempts.intValue();
      log.warn("Failed login attempt for userId={}. {} attempts remaining", userId, remaining);
    }
  }

  /**
   * Resets all login attempt tracking for a user.
   *
   * Called after successful login.
   * Clears both the failed counter and the lock key (if any).
   *
   * @param userId the user's DB ID
   *
   * Why delete both keys?
   * The lock key might exist if the user was locked, waited 30 min
   * (lock expired), then logged in successfully. The lock key is
   * gone (TTL expired), but the failed counter might have been
   * re-created by a failed attempt during the lock period.
   * Deleting both ensures a clean slate.
   *
   * Why not check if keys exist before deleting?
   * Redis DELETE on a non-existent key is a no-op — returns 0,
   * no error. Checking first would be two Redis calls instead of one.
   * Just delete — simpler, faster.
   */
  public void resetAttempts(Long userId) {
    redisTemplate.delete(FAILED_KEY_PREFIX + userId);
    redisTemplate.delete(LOCKED_KEY_PREFIX + userId);
  }
}
