package com.railway.auth_service.service.adminService;

import com.railway.auth_service.dto.pagination.PagedResponse;
import com.railway.auth_service.dto.request.admin.AdminFilterRequest;
import com.railway.auth_service.dto.request.admin.CreateAdminRequest;
import com.railway.auth_service.dto.request.admin.LogoutCurrentDeviceRequest;
import com.railway.auth_service.dto.response.admin.AdminSummaryResponse;
import com.railway.auth_service.dto.response.admin.CreateAdminResponse;
import com.railway.auth_service.dto.response.admin.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.admin.LogoutCurrentDeviceResponse;
import com.railway.auth_service.dto.response.admin.UpdateAdminStatusResponse;

public interface AdminService {

   LogoutCurrentDeviceResponse logoutCurrentDevice(LogoutCurrentDeviceRequest request);
   LogoutAllDeviceResponse logoutAllDevices();

   CreateAdminResponse createNewAdmin(CreateAdminRequest request);

  public PagedResponse<AdminSummaryResponse> getAdminList(AdminFilterRequest filter);

  public UpdateAdminStatusResponse updateAdminStatus(Long targetAdminId, boolean setActive);
}
