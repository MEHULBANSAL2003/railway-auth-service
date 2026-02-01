package com.railway.auth_service.controller;


import com.railway.auth_service.constants.ApiConstants;
import com.railway.auth_service.dto.request.admin.CreateAdminRequest;
import com.railway.auth_service.dto.request.admin.LogoutCurrentDeviceRequest;
import com.railway.auth_service.dto.response.admin.CreateAdminResponse;
import com.railway.auth_service.dto.response.admin.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.admin.LogoutCurrentDeviceResponse;
import com.railway.auth_service.exception.ApiResponse;
import com.railway.auth_service.service.adminService.AdminServiceImpl;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(ApiConstants.API_BASE)
@RequiredArgsConstructor
public class AdminController {

  private final AdminServiceImpl adminService;

 @PostMapping(ApiConstants.LOGOUT_CURRENT_DEVICE)
  public ResponseEntity<ApiResponse<LogoutCurrentDeviceResponse>> logoutCurrentDevice(@Valid @RequestBody LogoutCurrentDeviceRequest request) {
   log.info("Logout current device request received");
   LogoutCurrentDeviceResponse response = adminService.logoutCurrentDevice(request);
   return ResponseEntity.ok(ApiResponse.success(response));

 }


 @PostMapping(ApiConstants.LOGOUT_ALL_DEVICES)
  public ResponseEntity<ApiResponse<LogoutAllDeviceResponse>> logoutAllDevices() {
   log.info("Logout all devices request received");
   LogoutAllDeviceResponse response = adminService.logoutAllDevices();
   return ResponseEntity.ok(ApiResponse.success(response));

 }

 @PostMapping(ApiConstants.CREATE_NEW_ADMIN)
  public ResponseEntity<ApiResponse<CreateAdminResponse>> createNewAdmin(CreateAdminRequest request) {
   log.info("Create new admin request received");
   CreateAdminResponse response = adminService.createNewAdmin(request);
   return ResponseEntity.ok(ApiResponse.success(response));
  }

}
