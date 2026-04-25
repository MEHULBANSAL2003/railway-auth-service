package com.railway.auth_service.event;

import com.railway.auth_service.config.properties.AccountProperties;
import com.railway.common.event.auth.AccountDeletionEvent;
import com.railway.common.event.auth.AccountDeletionRequestEvent;
import com.railway.common.event.auth.EmailVerificationReminderEvent;
import com.railway.common.kafka.KafkaTopics;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthEventProducer {

  private final KafkaTemplate<String, Object> kafkaTemplate;
  private final AccountProperties accountProperties;

  public void publishEmailVerificationReminder(Long userId,
                                               String email,
                                               String fullName) {

    String correlationId = MDC.get("correlationId");
    String userIdStr = String.valueOf(userId);

    var event = new EmailVerificationReminderEvent(
      userIdStr, email, fullName, correlationId, Instant.now()
    );

    sendKafkaMsg(event, userIdStr, correlationId, KafkaTopics.Auth.EMAIL_VERIFICATION_REMINDER);
  }

  public void publishAccountDeletionEvent(Long userId,
                                          String email,
                                          String fullName){
    String correlationId = MDC.get("correlationId");
    String userIdStr = String.valueOf(userId);

    var event = new AccountDeletionEvent(
      userIdStr, email, fullName, correlationId, Instant.now()
    );

    sendKafkaMsg(event, userIdStr, correlationId, KafkaTopics.Auth.ACCOUNT_DELETION);
  }

  public void publishAccountDeletionRequestEvent(Long userId,
                                                 String email,
                                                 String fullName){
    String correlationId = MDC.get("correlationId");
    String userIdStr = String.valueOf(userId);

    var event = new AccountDeletionRequestEvent(
      userIdStr, email, fullName, correlationId, Instant.now(), accountProperties.getDeletionGracePeriodDays()
    );

    sendKafkaMsg(event, userIdStr, correlationId, KafkaTopics.Auth.ACCOUNT_DELETION_REQUEST);
  }

  private void sendKafkaMsg(Object event, String userId, String correlationId, String topic){
    kafkaTemplate.send(topic, userId, event)
      .whenComplete((result, ex) -> {

        if (correlationId != null) {
          MDC.put("correlationId", correlationId);
        }

        try {
          if (ex != null) {
            log.error("❌ Failed to publish event userId={} topic={} error={}",
              userId, topic, ex.getMessage());
          } else {
            log.info("✅ Published event userId={} topic={} offset={}",
              userId, topic, result.getRecordMetadata().offset());
          }
        }
        finally {
          MDC.remove("correlationId");
        }
      });
  }
}
