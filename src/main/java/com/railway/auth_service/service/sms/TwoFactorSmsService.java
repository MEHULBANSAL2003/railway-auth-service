package com.railway.auth_service.service.sms;

import com.railway.auth_service.config.properties.SmsProperties;
import com.railway.common.exception.ServiceException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Slf4j
@Service
@ConditionalOnProperty(name = "app.sms.provider", havingValue = "twofactor")
public class TwoFactorSmsService implements SmsService {

  // 2Factor OTP API endpoint
  // GET https://2factor.in/API/V1/{api_key}/SMS/{phone}/{otp}
  private static final String TWO_FACTOR_API_URL = "https://2factor.in/API/V1";

  private final SmsProperties.TwoFactor twoFactorConfig;
  private RestClient restClient;

  public TwoFactorSmsService(SmsProperties smsProperties) {
    this.twoFactorConfig = smsProperties.getTwoFactor();
  }

  @PostConstruct
  private void init() {
    this.restClient = RestClient.builder()
      .baseUrl(TWO_FACTOR_API_URL)
      .build();
    log.info("TwoFactorSmsService initialized");
  }

  @Override
  public void sendOtp(String to, String otp) {
    // 2Factor expects phone without country code
    String phone = to.startsWith("+91") ? to.substring(3) : to;
    phone = phone.startsWith("91") && phone.length() == 12 ? phone.substring(2) : phone;

    try {
      String response = restClient
        .get()
        .uri("/{apiKey}/SMS/{phone}/{otp}/AUTOGEN",
          twoFactorConfig.getApiKey(), phone, otp)
        .retrieve()
        .body(String.class);

      log.info("OTP SMS sent via 2Factor to {}: {}", maskPhone(to), response);

    } catch (Exception e) {
      log.error("2Factor SMS failed to {}: {}", maskPhone(to), e.getMessage());
      throw new ServiceException("Failed to send OTP SMS. Please try again later.");
    }
  }

  private String maskPhone(String phone) {
    if (phone == null || phone.length() < 4) return "****";
    return phone.substring(0, phone.length() - 4) + "****";
  }
}
