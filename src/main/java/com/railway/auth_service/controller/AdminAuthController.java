package com.railway.auth_service.controller;


import com.railway.auth_service.constant.ApiConstants;
import com.railway.auth_service.dto.request.GoogleLoginRequest;
import com.railway.auth_service.dto.response.AuthResponse;
import com.railway.common.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
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
@RequestMapping(ApiConstants.ADMIN_AUTH)
@RequiredArgsConstructor
public class AdminAuthController {

  @PostMapping(ApiConstants.ADMIN_GOOGLE_LOGIN)
  public ResponseEntity<ApiResponse<AuthResponse>> adminGoogleLogin(
    @Valid @RequestBody GoogleLoginRequest request,
    HttpServletRequest httpRequest) {

    String clientIp = extractClientIp(httpRequest);
    log.info("Admin Google login attempt from IP: {}", clientIp);

    //AuthResponse response = adminAuthService.googleLogin(request.getIdToken(), clientIp);

    return ResponseEntity.ok(ApiResponse.success());
  }






  private String extractClientIp(HttpServletRequest request) {
    String xff = request.getHeader("X-Forwarded-For");
    if (xff != null && !xff.isBlank()) {
      return xff.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
