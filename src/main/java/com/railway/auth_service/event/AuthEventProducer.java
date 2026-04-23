package com.railway.auth_service.event;

import com.railway.common.event.auth.EmailEvent;
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

    var event = new EmailEvent(
      String.valueOf(userId), email, fullName, correlationId, Instant.now()
    );

    sendKafkaMsg(event, correlationId,KafkaTopics.Auth.EMAIL_VERIFICATION_REMINDER);


  }


  public void publishAccountDeletionEvent(Long userId,
                                          String email,
                                          String fullName){
    String correlationId = MDC.get("correlationId");

    var event  = new EmailEvent( String.valueOf(userId), email, fullName, correlationId, Instant.now());

      sendKafkaMsg(event, correlationId, KafkaTopics.Auth.ACCOUNT_DELETION);
  }

  public void  publishAccountDeletionRequestEvent(Long userId,
                                          String email,
                                          String fullName){
    String correlationId = MDC.get("correlationId");

    var event  = new EmailEvent( String.valueOf(userId), email, fullName, correlationId, Instant.now());

    sendKafkaMsg(event, correlationId, KafkaTopics.Auth.ACCOUNT_DELETION_REQUEST);
  }


  private void sendKafkaMsg(EmailEvent event, String correlationId, String topic){
    kafkaTemplate.send(
        topic,
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
              event.userId(), ex.getMessage());
          } else {
            log.info("✅ Published reminder userId={} offset={}",
              event.userId(), result.getRecordMetadata().offset());
          }
        }
        finally {
          MDC.remove("correlationId");
        }
      });
  }
}
