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
@ConfigurationProperties(prefix = "app.email")
public class EmailProperties {

  @NotBlank(message = "Email provider must be configured (app.email.provider)")
  private String provider;

  private Resend resend = new Resend();
  private Ses ses = new Ses();

  @Getter
  @Setter
  public static class Resend {
    private String apiKey;
    private String fromAddress;
  }

  @Getter
  @Setter
  public static class Ses {
    private String fromAddress;
    private String region;
  }
}
