package com.railway.auth_service.scheduler;

import com.railway.auth_service.event.AuthEventProducer;
import com.railway.auth_service.model.enums.ActorType;
import com.railway.auth_service.model.enums.UserStatus;
import com.railway.auth_service.repository.UserRepository;
import com.railway.auth_service.service.status.UserStatusHistoryLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;


@Component
@RequiredArgsConstructor
@Slf4j
public class AccountDeleteScheduler {

  private final UserRepository userRepository;
  private final AuthEventProducer authEventProducer;
  private final UserStatusHistoryLogger statusHistoryLogger;


  @Scheduled(cron = "0 0 0 * * *", zone = "Asia/Kolkata")
  public void deletePendingAccounts() {
    log.info("🕐 Starting account deletion cron");

    var accountToBeDeleted = userRepository.findAllByStatus(UserStatus.DELETION_PENDING);

    log.info("Found {} users with deletion pending request", accountToBeDeleted.size());
    int success = 0;
    int failed = 0;
    int skipped = 0;

    Instant now = Instant.now();

    for (var user : accountToBeDeleted) {
      try {
        if (user.getStatus() != UserStatus.DELETION_PENDING) {
          continue;
        }

        // Only delete accounts whose deletion is scheduled for today or before
        if (user.getDeletionScheduledAt() == null || user.getDeletionScheduledAt().isAfter(now)) {
          log.debug("Skipping user {} - deletion scheduled for future ({})",
            user.getUserId(), user.getDeletionScheduledAt());
          skipped++;
          continue;
        }

        // Update user status to DELETED
        user.setDeletedAt(Instant.now());
        user.setStatus(UserStatus.DELETED);
        userRepository.save(user);

        // Log status change in history
        statusHistoryLogger.log(
          user,
          UserStatus.DELETION_PENDING,
          UserStatus.DELETED,
          "Account permanently deleted by scheduled cron job",
          null,  // No specific admin ID
          ActorType.SYSTEM,
          null   // No IP address for cron job
        );

        // Publish deletion event if email was verified
        if (user.isEmailVerified()) {
          authEventProducer.publishAccountDeletionEvent(
            user.getUserId(),
            user.getEmail(),
            user.getFullName()
          );
        }

        success++;
      } catch (Exception e) {
        // WHY catch per user and not outside the loop:
        // One failed user should not stop reminders for all others.
        log.error("❌ Failed to publish reminder userId={} error={}",
          user.getUserId(), e.getMessage());
        failed++;
      }
    }
    log.info("✅ Cron done. success={} failed={} skipped={} total={}",
      success, failed, skipped, accountToBeDeleted.size());
  }

}
