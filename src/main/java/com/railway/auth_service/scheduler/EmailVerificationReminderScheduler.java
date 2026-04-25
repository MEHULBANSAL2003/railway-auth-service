package com.railway.auth_service.scheduler;


import com.railway.auth_service.event.AuthEventProducer;
import com.railway.auth_service.model.enums.UserStatus;
import com.railway.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class EmailVerificationReminderScheduler {

  private final UserRepository userRepository;
  private final AuthEventProducer authEventProducer;


  @Scheduled(cron = "0 0 9 * * *", zone = "Asia/Kolkata")
  public void sendEmailVerificationReminders() {
    log.info("🕐 Starting email verification reminder cron");

    var unverifiedUsers = userRepository.findAllByEmailVerifiedFalse();
    log.info("Found {} users with unverified emails", unverifiedUsers.size());
    int success = 0;
    int failed = 0;

    for (var user : unverifiedUsers) {
      try {
        if (user.getStatus() != UserStatus.ACTIVE){
             continue;
        }
        authEventProducer.publishEmailVerificationReminder(
          user.getUserId(),
          user.getEmail(),
          user.getFullName()
        );
        success++;
        Thread.sleep(600);
      } catch (Exception e) {
        // WHY catch per user and not outside the loop:
        // One failed user should not stop reminders for all others.
        log.error("❌ Failed to publish reminder userId={} error={}",
          user.getUserId(), e.getMessage());
        failed++;
      }
    }
    log.info("✅ Cron done. success={} failed={} total={}",
      success, failed, unverifiedUsers.size());
  }

}
