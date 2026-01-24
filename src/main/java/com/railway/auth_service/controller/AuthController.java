package com.railway.auth_service.controller;


import com.railway.auth_service.constants.ApiConstants;
import com.railway.auth_service.dto.response.auth.GoogleAuthResponse;
import com.railway.auth_service.exception.ApiResponse;
import com.railway.auth_service.service.AuthServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(ApiConstants.AUTH_BASE)
public class AuthController {

  @Autowired
    AuthServiceImpl authService;

  @PostMapping(ApiConstants.LOGIN_ADMIN)
  public ResponseEntity<ApiResponse<GoogleAuthResponse>> adminLoginByEmail() {

      GoogleAuthResponse g = authService.googleTokenVerify();
    return ResponseEntity.ok(ApiResponse.success(g));
  }
}
