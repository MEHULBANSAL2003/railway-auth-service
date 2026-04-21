package com.railway.auth_service.controller;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class KafkaConnectionTest {

  @Autowired(required = false)
  private KafkaTemplate<String, Object> kafkaTemplate;

  @PostConstruct
  public void checkKafka() {
    if (kafkaTemplate == null) {
      log.error("❌ KafkaTemplate is NULL - Kafka is NOT configured");
    } else {
      log.info("✅ KafkaTemplate initialized - Kafka IS configured");

      // send a test message
      kafkaTemplate.send("test.topic", "hello", "Kafka is working!")
        .whenComplete((result, ex) -> {
          if (ex != null) {
            log.error("❌ Failed to send test message: {}", ex.getMessage());
          } else {
            log.info("✅ Test message sent to Kafka successfully!");
          }
        });
    }
  }
}
