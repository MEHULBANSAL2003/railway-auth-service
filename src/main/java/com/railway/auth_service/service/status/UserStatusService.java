package com.railway.auth_service.service.status;

import com.railway.auth_service.config.properties.AccountProperties;
import com.railway.auth_service.event.AuthEventProducer;
import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.enums.ActorType;
import com.railway.auth_service.model.enums.UserStatus;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.common.security.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserStatusService {

  private final UserRepository userRepository;
  private final RefreshTokenRepository refreshTokenRepository;
  private final UserStatusHistoryLogger historyLogger;
  private final Optional<TokenBlacklistService> blacklistService;
  private final AccountProperties accountProperties;
  private final AuthEventProducer authEventProducer;

  @Value("${app.jwt.access-token-expiry}")
  private long accessTokenExpiry;


  @Transactional
  public void changeStatus(User user,
                           UserStatus newStatus,
                           String reason,
                           Long changedById,
                           ActorType changedByType,
                           String ipAddress,
                           boolean killSessions) {

    UserStatus oldStatus = user.getStatus();

    user.setStatus(newStatus);
    user.setStatusReason(reason);
    user.setLastStatusChangeAt(Instant.now());
    if(newStatus == UserStatus.DELETION_PENDING){
      user.setDeletionReason(reason);
      user.setDeletionScheduledAt(
        Instant.now().plus(accountProperties.getDeletionGracePeriodDays(), ChronoUnit.DAYS)
      );
    }
    userRepository.save(user);

    if(newStatus == UserStatus.DELETION_PENDING && user.isEmailVerified()){
        authEventProducer.publishAccountDeletionRequestEvent(user.getUserId(), user.getFullName(), user.getEmail());
    }

    if (killSessions && oldStatus == UserStatus.ACTIVE) {
      killUserSessions(user.getUserId());
    }

    // Different bean → proxy intercepts → @Async works ✓
    historyLogger.log(user, oldStatus, newStatus, reason,
      changedById, changedByType, ipAddress);

    log.info("User status changed: userId={}, {} → {}, by={}:{}",
      user.getUserId(), oldStatus, newStatus, changedByType, changedById);
  }

  /**
   * Sets initial status for a newly registered user.
   *
   * NOT @Async — must run synchronously within the caller's transaction.
   * The user row is being created in the same transaction, so:
   *   1. user.setLastStatusChangeAt() must be flushed with the same transaction
   *   2. history insert's FK (user_id) must find the user in the same transaction
   *
   * Uses logSync (not async log) because the user row hasn't been committed yet.
   */
  public void setInitialActive(User user, String ipAddress) {
    historyLogger.logSync(user, null, UserStatus.ACTIVE,
      "Account created via registration",
      user.getUserId(), ActorType.USER, ipAddress);
  }

  private void killUserSessions(Long userId) {
    refreshTokenRepository.revokeAllByOwner(userId, "user");
    blacklistService.ifPresent(service ->
      service.setCutoff("user", userId, Duration.ofMillis(accessTokenExpiry))
    );
    log.debug("Sessions killed for userId={}", userId);
  }
}
