package com.railway.auth_service.service;

import com.railway.auth_service.dto.response.UserProfileResponse;

public interface UserService {

  void logout(String refreshToken, Long userId);

  UserProfileResponse getMyProfile(Long userId);
}
