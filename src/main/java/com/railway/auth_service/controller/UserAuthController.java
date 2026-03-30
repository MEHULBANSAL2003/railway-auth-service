package com.railway.auth_service.controller;


import com.railway.auth_service.constant.ApiConstants;
import com.railway.auth_service.dto.request.LoginRequest;
import com.railway.auth_service.dto.request.RegisterInitiateRequest;
import com.railway.auth_service.dto.request.RegisterResendRequest;
import com.railway.auth_service.dto.request.RegisterVerifyRequest;
import com.railway.auth_service.dto.response.AuthResponse;
import com.railway.auth_service.dto.response.RegisterInitiateResponse;
import com.railway.auth_service.service.UserAuthService;
import com.railway.common.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ApiConstants.USER_AUTH)
@RequiredArgsConstructor
public class UserAuthController {

  private final UserAuthService userAuthService;


  @PostMapping(ApiConstants.USER_REGISTER)
  public ResponseEntity<ApiResponse<RegisterInitiateResponse>> initiateRegistration(
    @Valid @RequestBody RegisterInitiateRequest request) {

    RegisterInitiateResponse response = userAuthService.initiateRegistration(request);

    return ResponseEntity.ok(ApiResponse.success(response));
  }


  @PostMapping(ApiConstants.USER_OTP_VERIFY)
  public ResponseEntity<ApiResponse<AuthResponse>> verifyRegistration(
    @Valid @RequestBody RegisterVerifyRequest request,
    HttpServletRequest httpRequest) {

    String clientIp = extractClientIp(httpRequest);
    AuthResponse response = userAuthService.verifyRegistration(request, clientIp);

    return ResponseEntity.status(HttpStatus.CREATED)
      .body(ApiResponse.success(response));
  }


  @PostMapping(ApiConstants.USER_RESEND_OTP)
  public ResponseEntity<ApiResponse<RegisterInitiateResponse>> resendOtp(
    @Valid @RequestBody RegisterResendRequest request) {

    RegisterInitiateResponse response = userAuthService.resendOtp(request);

    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @PostMapping(ApiConstants.USER_LOGIN)
  public ResponseEntity<ApiResponse<AuthResponse>> login(
    @Valid @RequestBody LoginRequest request,
    HttpServletRequest httpRequest) {

    String clientIp = extractClientIp(httpRequest);
    AuthResponse response = userAuthService.login(request, clientIp);

    return ResponseEntity.ok(ApiResponse.success(response));
  }

  private String extractClientIp(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For");
    if (forwarded != null && !forwarded.isBlank()) {
      return forwarded.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }

}
