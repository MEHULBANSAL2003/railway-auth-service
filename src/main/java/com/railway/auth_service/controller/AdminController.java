package com.railway.auth_service.controller;


import com.railway.auth_service.constants.ApiConstants;
import com.railway.auth_service.dto.pagination.PagedResponse;
import com.railway.auth_service.dto.request.admin.AdminFilterRequest;
import com.railway.auth_service.dto.request.admin.CreateAdminRequest;
import com.railway.auth_service.dto.request.admin.LogoutCurrentDeviceRequest;
import com.railway.auth_service.dto.response.admin.AdminSummaryResponse;
import com.railway.auth_service.dto.response.admin.CreateAdminResponse;
import com.railway.auth_service.dto.response.admin.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.admin.LogoutCurrentDeviceResponse;
import com.railway.auth_service.dto.response.admin.UpdateAdminStatusResponse;
import com.railway.common.exceptions.ApiResponse;
import com.railway.auth_service.service.adminService.AdminServiceImpl;
import com.railway.common.logging.Loggable;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(ApiConstants.API_BASE)
@RequiredArgsConstructor
@Loggable
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
 @PreAuthorize("hasRole('SUPER_ADMIN')")
  public ResponseEntity<ApiResponse<CreateAdminResponse>> createNewAdmin(@Valid @RequestBody CreateAdminRequest request) {
   log.info("Create new admin request received");
   CreateAdminResponse response = adminService.createNewAdmin(request);
   return ResponseEntity.ok(ApiResponse.success(response));
  }

//  @PatchMapping(ApiConstants.ADMIN_UPDATE_STATUS)
//  @PreAuthorize("hasRole('SUPER_ADMIN')")
//  public ResponseEntity<ApiResponse<CreateAdminResponse>> updateAdminStatus(@Valid @RequestBody CreateAdminRequest request) {
//    log.info("update admin status request received");
//    CreateAdminResponse response = adminService.createNewAdmin(request);
//    return ResponseEntity.ok(ApiResponse.success(response));
//  }

  @GetMapping(ApiConstants.ADMIN_LIST)
  @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
  public ResponseEntity<ApiResponse<PagedResponse<AdminSummaryResponse>>> getAllAdmins(
    @Valid @ModelAttribute AdminFilterRequest filter
  ) {
    log.info("Get admin list request received");
    PagedResponse<AdminSummaryResponse> response = adminService.getAdminList(filter);
    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @PostMapping(ApiConstants.ADMIN_UPDATE_STATUS)
  @PreAuthorize("hasRole('SUPER_ADMIN')")
  public ResponseEntity<ApiResponse<UpdateAdminStatusResponse>> updateAdminStatus(
    @PathVariable Long adminId, @RequestParam("setActive") Boolean setActive
  ) {
    log.info("Update admin status request | targetId={}", adminId);
    UpdateAdminStatusResponse response = adminService.updateAdminStatus(adminId,setActive);
    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @PostMapping(ApiConstants.ADMIN_UPDATE_ROLE)
  @PreAuthorize("hasRole('SUPER_ADMIN')")
  public ResponseEntity<ApiResponse<UpdateAdminStatusResponse>> updateAdminRole(
    @PathVariable Long adminId, @RequestParam("newRole") Boolean setActive
  ) {
    log.info("Update admin role request | targetId={}", adminId);
    UpdateAdminStatusResponse response = adminService.updateAdminStatus(adminId,setActive);
    return ResponseEntity.ok(ApiResponse.success(response));
  }



}
