package com.railway.auth_service.service;


import com.railway.auth_service.dto.response.auth.GoogleAuthResponse;
import org.springframework.stereotype.Service;

@Service
public interface AuthService {

  public GoogleAuthResponse googleTokenVerify();
}
