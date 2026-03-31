package com.railway.auth_service.service.email;

import com.railway.auth_service.config.properties.EmailProperties;
import com.railway.common.exception.ServiceException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.Map;

/**
 * Resend implementation of EmailService.
 *
 * Activated ONLY when app.email.provider=resend.
 * Makes HTTP POST to Resend REST API to send OTP emails.
 *
 * Resend API:
 *   POST https://api.resend.com/emails
 *   Auth: Bearer token
 *   Body: JSON { from, to, subject, html }
 *
 * Simpler than Twilio:
 *   - JSON body (not form-urlencoded)
 *   - Bearer token (not Basic auth)
 *   - One endpoint for everything
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "app.email.provider", havingValue = "resend")
public class ResendEmailService implements EmailService {

  private static final String RESEND_API_URL = "https://api.resend.com";

  /**
   * HTML template for OTP emails.
   *
   * Why HTML and not plain text?
   * HTML allows styling — bold OTP, clear layout, branded look.
   * Plain text works but looks unprofessional.
   *
   * Why inline styles and not CSS classes?
   * Email clients (Gmail, Outlook) strip <style> tags and external CSS.
   * Inline styles are the only reliable way to style emails.
   * This is an email-specific quirk — unlike web development.
   *
   * %s is replaced with the OTP value via String.format().
   */
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

  private final EmailProperties.Resend resendConfig;
  private RestClient restClient;

  public ResendEmailService(EmailProperties emailProperties) {
    this.resendConfig = emailProperties.getResend();
  }

  @PostConstruct
  private void init() {
    validateConfig();
    this.restClient = RestClient.builder()
      .baseUrl(RESEND_API_URL)
      .defaultHeader("Authorization", "Bearer " + resendConfig.getApiKey())
      .defaultHeader("Content-Type", "application/json")
      .build();

    log.info("ResendEmailService initialized with from: {}", resendConfig.getFromAddress());
  }

  @Override
  public void sendOtp(String to, String otp, String subject) {
    String html = String.format(OTP_EMAIL_TEMPLATE, otp);

    /*
     * Resend expects JSON body:
     * {
     *   "from": "onboarding@resend.dev",
     *   "to": "mehul@gmail.com",
     *   "subject": "Verify your email",
     *   "html": "<p>Your OTP is...</p>"
     * }
     *
     * Why Map and not a DTO class?
     * This is a simple 4-field request to an external API.
     * Creating a class for it is overkill. Map is sufficient.
     * If we add more fields later (attachments, cc, bcc),
     * then extract to a class. YAGNI.
     */
    Map<String, String> body = Map.of(
      "from", resendConfig.getFromAddress(),
      "to", to,
      "subject", subject,
      "html", html
    );

    try {
      restClient
        .post()
        .uri("/emails")
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .toBodilessEntity();

      log.info("OTP email sent to {}", maskEmail(to));

    } catch (Exception e) {
      log.error("Email delivery failed to {}. Error: {}", maskEmail(to), e.getMessage());
      throw new ServiceException("Failed to send OTP email. Please try again later.");
    }
  }

  private void validateConfig() {
    if (resendConfig.getApiKey() == null || resendConfig.getApiKey().isBlank()) {
      throw new IllegalStateException("Resend API key is not configured (app.email.resend.api-key)");
    }
    if (resendConfig.getFromAddress() == null || resendConfig.getFromAddress().isBlank()) {
      throw new IllegalStateException("Resend from address is not configured (app.email.resend.from-address)");
    }
  }

  /**
   * Masks email for logging.
   * "mehul@gmail.com" → "me****@gmail.com"
   */
  private String maskEmail(String email) {
    if (email == null || !email.contains("@")) return "****";
    int atIndex = email.indexOf("@");
    String local = email.substring(0, atIndex);
    String domain = email.substring(atIndex);
    if (local.length() <= 2) return local + "****" + domain;
    return local.substring(0, 2) + "****" + domain;
  }
}
