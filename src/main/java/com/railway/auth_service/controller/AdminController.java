package com.railway.auth_service.controller;

import com.railway.auth_service.constant.ApiConstants;
import com.railway.auth_service.dto.request.CreateAdminRequest;
import com.railway.auth_service.dto.request.RefreshRequest;
import com.railway.auth_service.dto.response.ActiveSessionResponse;
import com.railway.auth_service.dto.response.AdminResponse;
import com.railway.auth_service.dto.response.AdminUserDetailResponse;
import com.railway.auth_service.dto.response.CreateAdminResponse;
import com.railway.auth_service.dto.response.UserStatusHistoryResponse;
import com.railway.auth_service.service.AdminAuthService;
import com.railway.auth_service.service.AdminService;
import com.railway.common.dto.ApiResponse;
import com.railway.common.security.AuthPrincipal;
import com.railway.common.dto.PagedResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

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

  @PostMapping(ApiConstants.ADMIN_TOGGLE_STATUS)
  @PreAuthorize("hasRole('SUPER_ADMIN')")
  public ResponseEntity<ApiResponse<Map<String, Object>>> toggleStatus(
    @PathVariable Long adminId,
    @AuthenticationPrincipal AuthPrincipal principal) {

    log.info("Toggle admin status: adminId={}, by={}", adminId, principal.getId());

    Map<String, Object> response = adminService.toggleStatus(adminId, principal.getId());

    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @PostMapping(ApiConstants.ADMIN_CHANGE_ROLE)
  @PreAuthorize("hasRole('SUPER_ADMIN')")
  public ResponseEntity<ApiResponse<Map<String, Object>>> changeRole(
    @PathVariable Long adminId,
    @AuthenticationPrincipal AuthPrincipal principal) {

    log.info("Change admin role: adminId={}, by={}", adminId, principal.getId());

    Map<String, Object> response = adminService.changeRole(adminId, principal.getId());

    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @GetMapping
  @PreAuthorize("hasRole('SUPER_ADMIN')")
  public ResponseEntity<ApiResponse<PagedResponse<AdminResponse>>> listAdmins(
    @RequestParam(required = false) Integer page,
    @RequestParam(required = false) Integer size,
    @RequestParam(required = false) String sortBy,
    @RequestParam(required = false) String sortDir,
    @RequestParam(required = false) String role,
    @RequestParam(required = false) String department,
    @RequestParam(required = false) Boolean enabled,
    @RequestParam(required = false) String searchName,
    @RequestParam(required = false) String searchEmail,
    @RequestParam(required = false) String searchPhone,
    @RequestParam(required = false) String search) {

    PagedResponse<AdminResponse> response = adminService.listAdmins(
      page, size, sortBy, sortDir, role, department, enabled,
      searchName, searchEmail, searchPhone, search);

    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @GetMapping(ApiConstants.GET_MY_PROFILE)
  public ResponseEntity<ApiResponse<AdminResponse>> getOwnProfile(
    @AuthenticationPrincipal AuthPrincipal principal) {

    AdminResponse response = adminService.getOwnProfile(principal.getId());
    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @GetMapping(ApiConstants.GET_MY_SESSION)
  public ResponseEntity<ApiResponse<ActiveSessionResponse>> getActiveSession(
    @AuthenticationPrincipal AuthPrincipal principal) {

    log.info("Get active session: admin_id={}", principal.getId());
    ActiveSessionResponse response = adminService.getActiveSession(principal.getId());
    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @GetMapping(ApiConstants.ADMIN_BY_ID)
  @PreAuthorize("hasRole('SUPER_ADMIN')")
  public ResponseEntity<ApiResponse<AdminResponse>> getAdminById(
    @PathVariable Long adminId) {

    AdminResponse response = adminService.getAdminById(adminId);
    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @GetMapping(ApiConstants.GET_USER_PROFILE)
  @PreAuthorize("hasRole('SUPER_ADMIN') or hasRole('ADMIN')")
  public ResponseEntity<ApiResponse<AdminUserDetailResponse>> getUserById(
    @PathVariable Long userId) {

    AdminUserDetailResponse response = adminService.getUserById(userId);

    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @GetMapping(ApiConstants.USER_STATUS_HISTORY)
  @PreAuthorize("hasRole('SUPER_ADMIN') or hasRole('ADMIN')")
  public ResponseEntity<ApiResponse<PagedResponse<UserStatusHistoryResponse>>> getUserStatusHistory(
    @PathVariable Long userId,
    @RequestParam(required = false) Integer page,
    @RequestParam(required = false) Integer size,
    @RequestParam(required = false) String sortBy,
    @RequestParam(required = false) String sortDir,
    @RequestParam(required = false) Long adminId) {

    log.info("Get user status history: userId={}, page={}, size={}, sortBy={}, adminId={}",
      userId, page, size, sortBy, adminId);

    PagedResponse<UserStatusHistoryResponse> response = adminService.getUserStatusHistory(
      userId, page, size, sortBy, sortDir, adminId);

    return ResponseEntity.ok(ApiResponse.success(response));
  }


}
