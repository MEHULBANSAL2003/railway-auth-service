package com.railway.auth_service.service;

import com.railway.auth_service.dto.response.AuthResponse;

public interface AdminAuthService {

  AuthResponse googleLogin(String googleIdToken, String clientIp);

  AuthResponse refresh(String refreshToken, String clientIp);

  void logout(String refreshToken, Long adminId);
}
