package com.railway.auth_service.controller;


import com.railway.auth_service.constants.ApiConstants;
import com.railway.auth_service.dto.request.auth.GoogleAuthRequest;
import com.railway.auth_service.dto.response.auth.GoogleAuthResponse;
import com.railway.auth_service.exception.ApiResponse;
import com.railway.auth_service.service.authService.AuthServiceImpl;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(ApiConstants.AUTH_BASE)
public class AuthController {

  @Autowired
    AuthServiceImpl authServiceImpl;

  @PostMapping(ApiConstants.LOGIN_ADMIN)
  public ResponseEntity<ApiResponse<GoogleAuthResponse>> adminLoginByEmail(@Valid @RequestBody GoogleAuthRequest requestPayload) {
    log.info("Admin Google login request received");
    GoogleAuthResponse g = authServiceImpl.googleTokenVerify(requestPayload);
    return ResponseEntity.ok(ApiResponse.success(g));
  }
}
