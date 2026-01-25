package com.railway.auth_service.controller;


import com.railway.auth_service.constants.ApiConstants;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ApiConstants.API_BASE)
public class UserController {

  @GetMapping("/hello")
  public String hello(){
    return "hello";
  }

  @GetMapping("/hello2")
  @PreAuthorize("hasRole('ROLE_ADMIN')")
  public String hello2(){
    return "hello2";
  }

  @GetMapping("/hello3")
  @PreAuthorize("hasRole('ROLE_USER')")
  public String hello3(){
    return "hello3";
  }
}
