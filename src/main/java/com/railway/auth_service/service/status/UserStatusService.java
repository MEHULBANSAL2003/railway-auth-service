package com.railway.auth_service.service.status;

import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.enums.ActorType;
import com.railway.auth_service.model.enums.UserStatus;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
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

@Slf4j
@Service
@RequiredArgsConstructor
public class UserStatusService {

  private final UserRepository userRepository;
  private final RefreshTokenRepository refreshTokenRepository;
  private final UserStatusHistoryLogger historyLogger;
  private final Optional<TokenBlacklistService> blacklistService;

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
    userRepository.save(user);

    if (killSessions && oldStatus == UserStatus.ACTIVE) {
      killUserSessions(user.getUserId());
    }

    // Different bean → proxy intercepts → @Async works ✓
    historyLogger.log(user, oldStatus, newStatus, reason,
      changedById, changedByType, ipAddress);

    log.info("User status changed: userId={}, {} → {}, by={}:{}",
      user.getUserId(), oldStatus, newStatus, changedByType, changedById);
  }

  @Async("authAsyncExecutor")
  public void setInitialActive(User user, String ipAddress) {
    user.setLastStatusChangeAt(Instant.now());

    // Different bean → @Async works ✓
    historyLogger.log(user, null, UserStatus.ACTIVE,
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
