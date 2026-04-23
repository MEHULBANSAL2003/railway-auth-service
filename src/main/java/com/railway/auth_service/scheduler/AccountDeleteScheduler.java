package com.railway.auth_service.scheduler;

import com.railway.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;


@Component
@RequiredArgsConstructor
@Slf4j
public class AccountDeleteScheduler {

  private final UserRepository userRepository;

  @Scheduled(cron = "0 0 8 * * *", zone = "Asia/Kolkata")
  public void deletePendingAccounts() {

  }
}
