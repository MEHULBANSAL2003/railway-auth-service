package com.railway.auth_service.config.properties;


import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@Component
@ConfigurationProperties(prefix = "app.sms")
public class SmsProperties {

  @NotBlank(message = "SMS provider must be configured (app.sms.provider)")
  private String provider;

  private Twilio twilio = new Twilio();
  private Fast2Sms fast2Sms = new Fast2Sms();
  private TwoFactor twoFactor = new TwoFactor();

  @Getter
  @Setter
  public static class Twilio {
    private String accountSid;
    private String authToken;
    private String fromNumber;
  }

  @Getter
  @Setter
  public static class Fast2Sms {
    private String apiKey;
  }

  @Getter
  @Setter
  public static class TwoFactor {
    private String apiKey;
  }
}
