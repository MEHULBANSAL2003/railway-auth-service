package com.railway.auth_service.controller;


import com.railway.auth_service.constants.ApiConstants;
import com.railway.auth_service.dto.response.user.SecurityDebugResponse;
import com.railway.auth_service.utils.SecurityUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(ApiConstants.API_BASE)
public class AdminController {

  @GetMapping(ApiConstants.TEST_1)
  public ResponseEntity<SecurityDebugResponse> hello(){

    SecurityDebugResponse response = SecurityDebugResponse.builder()
      .adminId(SecurityUtils.getCurrentAdminId())
      .userId(SecurityUtils.getCurrentUserId())
      .id(SecurityUtils.getCurrentId())
      .isAdmin(SecurityUtils.isAdmin())
      .authorities(SecurityUtils.getCurrentAuthorities())
      .role(SecurityUtils.getCurrentRole())
      .isAuthenticated(SecurityUtils.isAuthenticated())
      .build();

    return ResponseEntity.ok(response);
  }


  @GetMapping(ApiConstants.TEST_2)
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<SecurityDebugResponse> hello2(){
    SecurityDebugResponse response = SecurityDebugResponse.builder()
      .adminId(SecurityUtils.getCurrentAdminId())
      .userId(SecurityUtils.getCurrentUserId())
      .id(SecurityUtils.getCurrentId())
      .isAdmin(SecurityUtils.isAdmin())
      .authorities(SecurityUtils.getCurrentAuthorities())
      .role(SecurityUtils.getCurrentRole())
      .isAuthenticated(SecurityUtils.isAuthenticated())
      .build();

    return ResponseEntity.ok(response);
  }

  @GetMapping(ApiConstants.TEST_3)
  @PreAuthorize("hasRole('USER')")
  public ResponseEntity<SecurityDebugResponse> hello3(){
    SecurityDebugResponse response = SecurityDebugResponse.builder()
      .adminId(SecurityUtils.getCurrentAdminId())
      .userId(SecurityUtils.getCurrentUserId())
      .id(SecurityUtils.getCurrentId())
      .isAdmin(SecurityUtils.isAdmin())
      .authorities(SecurityUtils.getCurrentAuthorities())
      .role(SecurityUtils.getCurrentRole())
      .isAuthenticated(SecurityUtils.isAuthenticated())
      .build();

    return ResponseEntity.ok(response);
  }
}
