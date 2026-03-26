package com.railway.auth_service.controller;

import com.railway.auth_service.constant.ApiConstants;
import com.railway.auth_service.dto.request.CreateAdminRequest;
import com.railway.auth_service.dto.request.RefreshRequest;
import com.railway.auth_service.dto.response.CreateAdminResponse;
import com.railway.auth_service.service.AdminAuthService;
import com.railway.auth_service.service.AdminService;
import com.railway.common.dto.ApiResponse;
import com.railway.common.security.AuthPrincipal;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Authenticated admin session operations.
 *
 * Lives under /api/admins (not /api/auth/admin) because
 * these endpoints REQUIRE a valid access token.
 *
 * POST /api/admins/logout → end current session
 */
@Slf4j
@RestController
@RequestMapping(ApiConstants.ADMINS_BASE)
@RequiredArgsConstructor
public class AdminController {

  private final AdminAuthService adminAuthService;
  private final AdminService adminService;

  @PostMapping(ApiConstants.ADMIN_LOGOUT)
  public ResponseEntity<ApiResponse<Void>> logout(
    @Valid @RequestBody RefreshRequest request,
    @AuthenticationPrincipal AuthPrincipal principal) {

    log.info("Admin logout: admin_id={}", principal.getId());
    adminAuthService.logout(request.getRefreshToken(), principal.getId());

    return ResponseEntity.ok(ApiResponse.success());
  }

  @PostMapping
  @PreAuthorize("hasRole('SUPER_ADMIN')")
  public ResponseEntity<ApiResponse<CreateAdminResponse>> createAdmin(
    @Valid @RequestBody CreateAdminRequest request,
    @AuthenticationPrincipal AuthPrincipal principal) {

    log.info("Create admin request by super_admin id={}", principal.getId());

    CreateAdminResponse response = adminService.createAdmin(request, principal.getId());

    return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(response));
  }
}
