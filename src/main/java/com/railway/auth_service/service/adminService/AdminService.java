package com.railway.auth_service.service.adminService;

import com.railway.auth_service.dto.request.admin.LogoutCurrentDeviceRequest;
import com.railway.auth_service.dto.response.admin.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.admin.LogoutCurrentDeviceResponse;

public interface AdminService {

   LogoutCurrentDeviceResponse logoutCurrentDevice(LogoutCurrentDeviceRequest request);
   LogoutAllDeviceResponse logoutAllDevices();
}
