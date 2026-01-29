package com.railway.auth_service.controller;
import com.railway.auth_service.constants.ApiConstants;
import com.railway.auth_service.dto.request.user.LogoutCurrentDeviceRequest;
import com.railway.auth_service.dto.response.user.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.user.LogoutCurrentDeviceResponse;
import com.railway.auth_service.exception.ApiResponse;
import com.railway.auth_service.service.userAdminService.UserAdminServiceImpl;
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
public class UserAdminController {

  private final UserAdminServiceImpl userService;


  @PostMapping(ApiConstants.LOGOUT_CURRENT_DEVICE)
  public ResponseEntity<ApiResponse<LogoutCurrentDeviceResponse>> logoutCurrentDevice(@Valid @RequestBody LogoutCurrentDeviceRequest request) {
    log.info("Logout from current device request received");
     LogoutCurrentDeviceResponse  response= userService.logoutFromCurrentDevice(request.getRefreshToken());
    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @PostMapping(ApiConstants.LOGOUT_ALL_DEVICES)
  public ResponseEntity<ApiResponse<LogoutAllDeviceResponse>> logoutAllDevices() {
    log.info("Logout from all devices request received");
    LogoutAllDeviceResponse response = userService.logoutFromAllDevices();
    return ResponseEntity.ok(ApiResponse.success(response));
  }

}
