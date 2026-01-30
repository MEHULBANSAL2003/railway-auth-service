package com.railway.auth_service.service.authService;


import com.railway.auth_service.dto.request.auth.GoogleAuthRequest;
import com.railway.auth_service.dto.request.auth.RefreshTokenRequest;
import com.railway.auth_service.dto.response.auth.GoogleAuthResponse;
import com.railway.auth_service.dto.response.auth.RefreshTokenResponse;
import org.springframework.stereotype.Service;

@Service
public interface AuthService {

  GoogleAuthResponse googleTokenVerify(GoogleAuthRequest request);

  RefreshTokenResponse refreshAccessToken(RefreshTokenRequest request);
}
