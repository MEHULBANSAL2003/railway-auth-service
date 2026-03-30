package com.railway.auth_service.service.sms;

public interface SmsService {

  void sendOtp(String to, String otp);
}
