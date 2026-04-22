package com.railway.auth_service.event;


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

  public void publishEmailVerificationReminder(Long userId,
                                               String email,
                                               String fullName) {

    String correlationId = MDC.get("correlationId");

    var event = new EmailVerificationReminderEvent(
      String.valueOf(userId), email, fullName, correlationId, Instant.now()
    );



    kafkaTemplate.send(
        KafkaTopics.Auth.EMAIL_VERIFICATION_REMINDER,
        event.userId(),
        event
      )
      .whenComplete((result, ex) -> {

        if (correlationId != null) {
          MDC.put("correlationId", correlationId);
        }

        try {
          if (ex != null) {
            log.error("❌ Failed to publish reminder userId={} error={}",
              userId, ex.getMessage());
          } else {
            log.info("✅ Published reminder userId={} offset={}",
              userId, result.getRecordMetadata().offset());
          }
        }
        finally {
          MDC.remove("correlationId");
        }
      });
  }
}
