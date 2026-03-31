package com.railway.auth_service.service.status;

import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.entity.UserStatusHistory;
import com.railway.auth_service.model.enums.ActorType;
import com.railway.auth_service.model.enums.UserStatus;
import com.railway.auth_service.repository.UserStatusHistoryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * Async logger for user status history.
 *
 * Separate class from UserStatusService because @Async only works
 * when called from a DIFFERENT bean. Spring proxies intercept
 * external calls but not internal (same-class) calls.
 *
 * This class has ONE job: write history rows in a background thread.
 * Single Responsibility.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserStatusHistoryLogger {

  private final UserStatusHistoryRepository historyRepository;

  @Async("authAsyncExecutor")
  public void log(User user,
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

      log.debug("Status history logged: userId={}, {} → {}",
        user.getUserId(), oldStatus, newStatus);

    } catch (Exception e) {
      log.error("Failed to log status history for userId={}: {}",
        user.getUserId(), e.getMessage());
    }
  }
}
