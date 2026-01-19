package com.railway.auth_service.controller;


import com.railway.auth_service.constants.ApiConstants;
import com.railway.auth_service.exception.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(ApiConstants.AUTH_BASE)
public class AuthController {


  @PostMapping(ApiConstants.USER_SIGNUP_GET_OTP)
  public ResponseEntity<ApiResponse<Object>> signupGetOtp() {
    Map<String, Object> result = new HashMap<>();
    result.put("name", "mehul");
    return ResponseEntity.ok(ApiResponse.success(result));
  }
}
