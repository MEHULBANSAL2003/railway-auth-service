package com.railway.auth_service.controller;


import com.railway.auth_service.constants.ApiConstants;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ApiConstants.AUTH_BASE)
public class AuthController {

  @PostMapping(ApiConstants.SIGN_UP)
  public String signupGetOtp(){
    return "hello";
  };
}
