package com.railway.auth_service.controller;

import com.railway.auth_service.constant.ApiConstants;
import com.railway.auth_service.dto.request.RefreshRequest;
import com.railway.auth_service.service.UserService;
import com.railway.common.dto.ApiResponse;
import com.railway.common.security.AuthPrincipal;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Authenticated user endpoints.
 *
 * All endpoints require a valid JWT access token.
 * Spring Security enforces this via .requestMatchers("/api/user/**").authenticated()
 *
 * POST /api/user/logout → end current session
 * GET  /api/user/me     → get own profile (future)
 * PUT  /api/user/profile → update profile (future)
 */
@Slf4j
@RestController
@RequestMapping(ApiConstants.USERS_BASE)
@RequiredArgsConstructor
public class UserController {

  private final UserService userService;

  @PostMapping(ApiConstants.ADMIN_LOGOUT)
  public ResponseEntity<ApiResponse<Void>> logout(
    @Valid @RequestBody RefreshRequest request,
    @AuthenticationPrincipal AuthPrincipal principal) {

    log.info("User logout: user_id={}", principal.getId());
    userService.logout(request.getRefreshToken(), principal.getId());

    return ResponseEntity.ok(ApiResponse.success());
  }
}
