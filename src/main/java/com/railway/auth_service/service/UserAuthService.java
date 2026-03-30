package com.railway.auth_service.service;

import com.railway.auth_service.dto.request.LoginRequest;
import com.railway.auth_service.dto.request.RegisterInitiateRequest;
import com.railway.auth_service.dto.request.RegisterResendRequest;
import com.railway.auth_service.dto.request.RegisterVerifyRequest;
import com.railway.auth_service.dto.response.AuthResponse;
import com.railway.auth_service.dto.response.RegisterInitiateResponse;

/**
 * User authentication operations.
 *
 * Why an interface?
 *   - Controller depends on abstraction, not implementation
 *   - Mockable in unit tests without Spring context
 *   - Consistent with AdminAuthService pattern
 *
 * Login methods will be added here later.
 */
public interface UserAuthService {

  RegisterInitiateResponse initiateRegistration(RegisterInitiateRequest request);

  AuthResponse verifyRegistration(RegisterVerifyRequest request, String clientIp);

  RegisterInitiateResponse resendOtp(RegisterResendRequest request);

  AuthResponse login(LoginRequest request, String clientIp);

  AuthResponse refresh(String refreshToken, String clientIp);

}
