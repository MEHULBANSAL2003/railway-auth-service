package com.railway.auth_service.service.sms;


import com.railway.auth_service.config.properties.SmsProperties;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Base64;

@Slf4j
@Service
@ConditionalOnProperty(name = "app.sms.provider", havingValue = "twilio")
public class TwilioSmsService implements SmsService {

  private static final String TWILIO_API_BASE = "https://api.twilio.com/2010-04-01/Accounts";
  private static final String OTP_MESSAGE_TEMPLATE = "Your railway booking OTP is %s. Valid for 5 minutes.";

  private final SmsProperties.Twilio twilioConfig;
  private RestClient restClient;

  public TwilioSmsService(SmsProperties smsProperties) {
    this.twilioConfig = smsProperties.getTwilio();
  }

  @PostConstruct
  private void init() {
    validateConfig();
    this.restClient = buildRestClient();
    log.info("TwilioSmsService initialized for account: {}",
      twilioConfig.getAccountSid().substring(0, 8) + "...");
  }

  @Override
  public void sendOtp(String to, String otp){
    String message = String.format(OTP_MESSAGE_TEMPLATE, otp);
    MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
    formData.add("From", twilioConfig.getFromNumber());
    formData.add("To", to);
    formData.add("Body", message);

    try {
      restClient
        .post()
        .uri("/Messages.json")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body(formData)
        .retrieve()
        .toBodilessEntity();

      log.info("OTP sent successfully to {}", maskPhone(to));

    } catch (Exception e) {
      log.warn("SMS delivery failed to {}. OTP: {} | Error: {}",
        maskPhone(to), otp, e.getMessage());
    }

  }

  private void validateConfig() {
    if (twilioConfig.getAccountSid() == null || twilioConfig.getAccountSid().isBlank()) {
      throw new IllegalStateException("Twilio account SID is not configured (app.sms.twilio.account-sid)");
    }
    if (twilioConfig.getAuthToken() == null || twilioConfig.getAuthToken().isBlank()) {
      throw new IllegalStateException("Twilio auth token is not configured (app.sms.twilio.auth-token)");
    }
    if (twilioConfig.getFromNumber() == null || twilioConfig.getFromNumber().isBlank()) {
      throw new IllegalStateException("Twilio from number is not configured (app.sms.twilio.from-number)");
    }
  }

  private RestClient buildRestClient() {
    String credentials = twilioConfig.getAccountSid() + ":" + twilioConfig.getAuthToken();
    String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());

    return RestClient.builder()
      .baseUrl(TWILIO_API_BASE + "/" + twilioConfig.getAccountSid())
      .defaultHeader("Authorization", "Basic " + encodedCredentials)
      .build();
  }

  private String maskPhone(String phone) {
    if (phone == null || phone.length() < 6) return "****";
    return phone.substring(0, 3) + "****" + phone.substring(phone.length() - 4);
  }
}
