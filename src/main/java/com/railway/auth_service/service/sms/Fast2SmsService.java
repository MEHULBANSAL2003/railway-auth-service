package com.railway.auth_service.service.sms;

import com.railway.auth_service.config.properties.SmsProperties;
import com.railway.common.exception.ServiceException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Slf4j
@Service
@ConditionalOnProperty(name = "app.sms.provider", havingValue = "fast2sms")
public class Fast2SmsService implements SmsService {

  private static final String FAST2SMS_API_URL = "https://www.fast2sms.com/dev/bulkV2";

  private final SmsProperties.Fast2Sms fast2SmsConfig;
  private RestClient restClient;

  public Fast2SmsService(SmsProperties smsProperties) {
    this.fast2SmsConfig = smsProperties.getFast2Sms();
  }

  @PostConstruct
  private void init() {
    this.restClient = RestClient.builder()
      .build();
    log.info("Fast2SmsService initialized");
  }

  @Override
  public void sendOtp(String to, String otp) {
    // Fast2SMS expects phone without country code
    String phone = to.startsWith("+91") ? to.substring(3) : to;

    try {
      // Fast2SMS OTP route — no DLT needed
      String url = FAST2SMS_API_URL +
        "?authorization=" + fast2SmsConfig.getApiKey() +
        "&variables_values=" + otp +
        "&route=otp" +
        "&numbers=" + phone;

      String response = restClient
        .get()
        .uri(url)
        .header("cache-control", "no-cache")
        .retrieve()
        .body(String.class);

      log.info("OTP SMS sent via Fast2SMS to {}: {}", maskPhone(to), response);

    } catch (Exception e) {
      log.error("Fast2SMS failed to {}: {}", maskPhone(to), e.getMessage());
      throw new ServiceException("Failed to send OTP SMS. Please try again later.");
    }
  }

  private String maskPhone(String phone) {
    if (phone == null || phone.length() < 4) return "****";
    return phone.substring(0, phone.length() - 4) + "****";
  }
}
