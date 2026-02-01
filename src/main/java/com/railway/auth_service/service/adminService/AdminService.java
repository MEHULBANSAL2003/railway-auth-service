package com.railway.auth_service.service.adminService;

import com.railway.auth_service.dto.request.user.LogoutCurrentDeviceRequest;
import com.railway.auth_service.dto.response.user.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.user.LogoutCurrentDeviceResponse;

public interface AdminService {

   LogoutCurrentDeviceResponse logoutCurrentDevice(LogoutCurrentDeviceRequest request);
   LogoutAllDeviceResponse logoutAllDevices();
}
