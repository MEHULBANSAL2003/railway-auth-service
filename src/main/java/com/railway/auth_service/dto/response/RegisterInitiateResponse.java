package com.railway.auth_service.dto.response;

import lombok.Builder;
import lombok.Getter;

/**
 * Response for /register/initiate and /register/resend.
 *
 * Everything is backend-driven — frontend hardcodes nothing:
 *   - expiresInSeconds → countdown timer duration
 *   - otpLength → number of OTP input boxes to render
 *   - message → display message
 *
 * Why backend-driven?
 * If you change OTP from 6 to 4 digits, only change backend config.
 * Frontend reads otpLength and renders 4 boxes instead of 6.
 * No frontend deployment needed for config changes.
 */
@Getter
@Builder
public class RegisterInitiateResponse {

  private String message;
  private int expiresInSeconds;
  private int otpLength;
}
