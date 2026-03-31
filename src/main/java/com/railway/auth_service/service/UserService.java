package com.railway.auth_service.service;

public interface UserService {

  void logout(String refreshToken, Long userId);
}
