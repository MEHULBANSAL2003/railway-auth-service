package com.railway.auth_service.controller;


import com.railway.auth_service.constants.ApiConstants;
import com.railway.auth_service.dto.request.auth.GoogleAuthRequest;
import com.railway.auth_service.dto.request.auth.RefreshTokenRequest;
import com.railway.auth_service.dto.response.auth.GoogleAuthResponse;
import com.railway.auth_service.dto.response.auth.RefreshTokenResponse;
import com.railway.common.exceptions.ApiResponse;
import com.railway.auth_service.service.authService.AuthServiceImpl;
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
@RequestMapping(ApiConstants.AUTH_BASE)
@RequiredArgsConstructor
public class AuthController {

  private final AuthServiceImpl authServiceImpl;

  @PostMapping(ApiConstants.LOGIN_ADMIN)
  public ResponseEntity<ApiResponse<GoogleAuthResponse>> adminLoginByEmail(@Valid @RequestBody GoogleAuthRequest request) {
    log.info("Admin Google login request received");
    GoogleAuthResponse response = authServiceImpl.googleTokenVerify(request);
    return ResponseEntity.ok(ApiResponse.success(response));
  }

  @PostMapping(ApiConstants.REFRESH_ACCESS_TOKEN)
  public ResponseEntity<ApiResponse<RefreshTokenResponse>> refreshAccessToken(@Valid @RequestBody RefreshTokenRequest request){
    log.info("Refresh Token request received");
    RefreshTokenResponse response = authServiceImpl.refreshAccessToken(request);
    return ResponseEntity.ok(ApiResponse.success(response));
  }

}
