package com.railway.auth_service.service.status;

import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.entity.UserStatusHistory;
import com.railway.auth_service.model.enums.ActorType;
import com.railway.auth_service.model.enums.UserStatus;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.auth_service.repository.UserStatusHistoryRepository;
import com.railway.common.security.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Central service for all user status changes.
 *
 * Why a separate service?
 * Status changes happen from multiple places:
 *   - Admin locks/disables/suspends
 *   - User deactivates/deletes
 *   - Login auto-reactivates
 *   - Registration sets initial ACTIVE
 *
 * All of them need:
 *   - Update user status + reason + lastStatusChangeAt
 *   - Log history (async)
 *   - Kill sessions (when moving away from ACTIVE)
 *
 * Single Responsibility: one place for all status logic.
 * DRY: no duplicated session-kill or history-log code.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserStatusService {

  private final UserRepository userRepository;
  private final UserStatusHistoryRepository historyRepository;
  private final RefreshTokenRepository refreshTokenRepository;
  private final Optional<TokenBlacklistService> blacklistService;

  @Value("${app.jwt.access-token-expiry}")
  private long accessTokenExpiry;

  /**
   * Changes a user's status synchronously and logs history asynchronously.
   *
   * This is the ONLY method that modifies user status.
   * Every status change in the entire system goes through here.
   * Single point of control.
   *
   * @param user           the user entity (must be managed/attached)
   * @param newStatus      the new status to set
   * @param reason         why (nullable for ACTIVE)
   * @param changedById    who made the change
   * @param changedByType  admin, user, or system
   * @param ipAddress      IP of the actor (nullable for system)
   * @param killSessions   whether to revoke tokens and blacklist
   */
  @Transactional
  public void changeStatus(User user, UserStatus newStatus, String reason, Long changedById, ActorType changedByType, String ipAddress, boolean killSessions) {

    UserStatus oldStatus = user.getStatus();

    // Update user entity
    user.setStatus(newStatus);
    user.setStatusReason(reason);
    user.setLastStatusChangeAt(Instant.now());
    userRepository.save(user);

    // Kill sessions if moving away from ACTIVE
    if (killSessions && oldStatus == UserStatus.ACTIVE) {
      killUserSessions(user.getUserId());
    }

    // Log history asynchronously
    logHistoryAsync(user, oldStatus, newStatus, reason, changedById, changedByType, ipAddress);

    log.info("User status changed: userId={}, {} → {}, by={}:{}",
      user.getUserId(), oldStatus, newStatus, changedByType, changedById);
  }

  /**
   * Convenience method for initial registration.
   * No old status, no session kill needed.
   */

  @Async("authAsyncExecutor")
  public void setInitialActive(User user, String ipAddress) {
    // Don't use changeStatus here — user is being created,
    // status is already ACTIVE from builder. Just log history.
    user.setLastStatusChangeAt(Instant.now());
    logHistoryAsync(user, null, UserStatus.ACTIVE, "Account created via registration",
      user.getUserId(), ActorType.USER, ipAddress);
  }

  /**
   * Logs status change history in a background thread.
   *
   * Why async?
   * History is audit/analytics — nice to have, not critical.
   * The main flow (status change + session kill) must be fast.
   * If history logging fails, the status change still succeeded.
   * We log the error and move on.
   *
   * Why @Async on a separate method and not on changeStatus?
   * changeStatus must be synchronous — the caller needs to know
   * the status was updated before returning a response.
   * Only the history INSERT is async.
   */
  @Async("authAsyncExecutor")
  public void logHistoryAsync(User user,
                              UserStatus oldStatus,
                              UserStatus newStatus,
                              String reason,
                              Long changedById,
                              ActorType changedByType,
                              String ipAddress) {
    try {
      UserStatusHistory history = UserStatusHistory.builder()
        .user(user)
        .oldStatus(oldStatus)
        .newStatus(newStatus)
        .reason(reason)
        .changedById(changedById)
        .changedByType(changedByType)
        .ipAddress(ipAddress)
        .changedAt(Instant.now())
        .build();

      historyRepository.save(history);

      log.debug("Status history logged: userId={}, {} → {}", user.getUserId(), oldStatus, newStatus);

    } catch (Exception e) {
      // Never let history failure affect the main flow
      log.error("Failed to log status history for userId={}: {}", user.getUserId(), e.getMessage());
    }
  }

  /**
   * Kills all active sessions for a user.
   * Revokes refresh tokens + blacklists access tokens.
   */
  private void killUserSessions(Long userId) {
    refreshTokenRepository.revokeAllByOwner(userId, "user");

    blacklistService.ifPresent(service ->
      service.setCutoff("user", userId, Duration.ofMillis(accessTokenExpiry))
    );

    log.debug("Sessions killed for userId={}", userId);
  }
}
