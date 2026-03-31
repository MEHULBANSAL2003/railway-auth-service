package com.railway.auth_service.service.email;

public interface EmailService {

  void sendOtp(String to, String otp, String subject);
}
