package com.railway.auth_service.service.userService;

import com.railway.auth_service.dto.response.user.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.user.LogoutCurrentDeviceResponse;

public interface UserService {

  public LogoutCurrentDeviceResponse logoutFromCurrentDevice(String token);
  public LogoutAllDeviceResponse logoutFromAllDevices();
}
