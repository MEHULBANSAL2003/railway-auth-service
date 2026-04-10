package com.railway.auth_service.service.email;


import com.railway.auth_service.config.properties.EmailProperties;
import com.railway.common.exception.ServiceException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.SendEmailRequest;
import software.amazon.awssdk.services.ses.model.SesException;

@Slf4j
@Service
@ConditionalOnProperty(name = "app.email.provider", havingValue = "ses")
public class SesEmailService implements EmailService {

  private static final String OTP_EMAIL_TEMPLATE = """
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #333;">Railway Booking</h2>
          <p style="color: #555; font-size: 16px;">Your verification code is:</p>
          <div style="background: #f4f4f4; padding: 16px; text-align: center; border-radius: 8px; margin: 20px 0;">
              <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #333;">%s</span>
          </div>
          <p style="color: #888; font-size: 14px;">This code expires in 5 minutes. Do not share it with anyone.</p>
      </div>
      """;

  private final EmailProperties.Ses sesConfig;
  private SesClient sesClient;

  public SesEmailService(EmailProperties emailProperties) {
    this.sesConfig = emailProperties.getSes();
  }

  @PostConstruct
  private void init() {
    this.sesClient = SesClient.builder()
      .region(Region.of(sesConfig.getRegion()))
      .build();
    log.info("SesEmailService initialized with from: {}", sesConfig.getFromAddress());
  }

  @Override
  public void sendOtp(String to, String otp, String subject) {
    String html = String.format(OTP_EMAIL_TEMPLATE, otp);

    try {
      SendEmailRequest request = SendEmailRequest.builder()
        .source(sesConfig.getFromAddress())
        .destination(d -> d.toAddresses(to))
        .message(m -> m
          .subject(c -> c.data(subject))
          .body(b -> b.html(c -> c.data(html)))
        )
        .build();

      sesClient.sendEmail(request);
      log.info("OTP email sent via SES to {}", maskEmail(to));

    } catch (SesException e) {
      log.error("SES email failed to {}: {}", maskEmail(to), e.getMessage());
      throw new ServiceException("Failed to send OTP email. Please try again later.");
    }
  }


  private String maskEmail(String email) {
    if (email == null || !email.contains("@")) return "****";
    int atIndex = email.indexOf("@");
    String local = email.substring(0, atIndex);
    String domain = email.substring(atIndex);
    if (local.length() <= 2) return local + "****" + domain;
    return local.substring(0, 2) + "****" + domain;
  }
}
