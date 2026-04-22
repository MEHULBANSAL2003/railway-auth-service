package com.railway.auth_service.config;


import com.railway.common.kafka.KafkaTopics;
import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class KafkaTopicConfig {

  @Bean
  public NewTopic emailVerificationReminderTopic() {
    return TopicBuilder
      .name(KafkaTopics.Auth.EMAIL_VERIFICATION_REMINDER)
      .partitions(1)
      .replicas(1)
      .build();
  }
}
