package com.railway.auth_service.config.googleOAuthConfig;


import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
public class GoogleOAuthConfig {
  @Value("${google.client.id}")
  private String clientId;

  @Value("${google.client.secret}")
  private String clientSecret;

  @Value("${google.redirect.uri:http://localhost:3000/auth/google/callback}")
  private String redirectUri;
}
