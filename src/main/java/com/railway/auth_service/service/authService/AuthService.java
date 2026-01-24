package com.railway.auth_service.service.authService;


import com.railway.auth_service.dto.request.auth.GoogleAuthRequest;
import com.railway.auth_service.dto.response.auth.GoogleAuthResponse;
import org.springframework.stereotype.Service;

@Service
public interface AuthService {

  public GoogleAuthResponse googleTokenVerify(GoogleAuthRequest request);
}
