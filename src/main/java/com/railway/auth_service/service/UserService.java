package com.railway.auth_service.service;

import com.railway.auth_service.dto.request.ChangePasswordRequest;
import com.railway.auth_service.dto.response.RegisterInitiateResponse;
import com.railway.auth_service.dto.response.UserProfileResponse;

public interface UserService {

  void logout(String refreshToken, Long userId);

  UserProfileResponse getMyProfile(Long userId);

  void changePassword(Long userId, ChangePasswordRequest request);

  RegisterInitiateResponse sendEmailOtp(Long userId);

  void verifyEmailOtp(Long userId, String otp);

  RegisterInitiateResponse resendEmailOtp(Long userId);
}
