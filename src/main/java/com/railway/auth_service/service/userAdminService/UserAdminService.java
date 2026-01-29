package com.railway.auth_service.service.userAdminService;

import com.railway.auth_service.dto.response.user.AdminUpdateStatusResponse;
import com.railway.auth_service.dto.response.user.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.user.LogoutCurrentDeviceResponse;

public interface UserAdminService {

  public LogoutCurrentDeviceResponse logoutFromCurrentDevice(String token);
  public LogoutAllDeviceResponse logoutFromAllDevices();

  public AdminUpdateStatusResponse updateUserStatus(Long id, Boolean status);
}
