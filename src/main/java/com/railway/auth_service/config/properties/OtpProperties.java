package com.railway.auth_service.config.properties;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@Component
@ConfigurationProperties(prefix = "app.otp")
public class OtpProperties {

  private boolean useFixed = false;

  private String fixedValue = "111111";

  private int length = 6;

  private int expirySeconds = 300;

  private int cooldownSeconds = 300;

  private int maxAttempts = 3;

  private int resendCooldownSeconds = 30;

  private int maxResends = 3;

}
