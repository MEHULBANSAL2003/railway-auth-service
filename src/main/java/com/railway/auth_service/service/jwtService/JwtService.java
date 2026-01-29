// service/JwtService.java
package com.railway.auth_service.service.jwtService;

import com.railway.auth_service.entity.UserEntity;
import com.railway.auth_service.enums.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class JwtService {

  @Value("${jwt.secret}")
  private String secret;

  @Value("${jwt.access-token.expiry-ms}")
  private Long accessTokenExpiry;

  @Value("${jwt.refresh-token.expiry-ms}")
  private Long refreshTokenExpiry;

  private Key getSigningKey() {
    return Keys.hmacShaKeyFor(secret.getBytes());
  }

  /**
   * Generate access token with user claims
   * Payload includes: userId, email, role (ROLE_ADMIN/ROLE_USER)
   */
  public String generateAccessToken(Long id, String email, Role role,String type) {
    Map<String, Object> claims = new HashMap<>();
    if ("ADMIN".equalsIgnoreCase(type)) {
      claims.put("adminId", id);
    } else if ("USER".equalsIgnoreCase(type)) {
      claims.put("userId", id);
    }
    claims.put("id", id);
    claims.put("role", role.name());
    return Jwts.builder()
      .setClaims(claims)
      .setSubject(email)
      .setIssuedAt(new Date())
      .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiry))
      .signWith(getSigningKey(), SignatureAlgorithm.HS256)
      .compact();
  }

  /**
   * Generate refresh token
   */
  public String generateRefreshToken(UserEntity user) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("id", user.getId());

    return Jwts.builder()
      .setClaims(claims)
      .setSubject(user.getEmail())
      .setIssuedAt(new Date())
      .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiry))
      .signWith(getSigningKey(), SignatureAlgorithm.HS256)
      .compact();
  }

  /**
   * Validate and extract claims from token
   */
  public Claims validateToken(String token) {
    return Jwts.parserBuilder()
      .setSigningKey(getSigningKey())
      .build()
      .parseClaimsJws(token)
      .getBody();
  }

  public Long id(String token) {
    return validateToken(token).get("id", Long.class);
  }

  /**
   * Extract role from token
   */
  public String extractRole(String token) {
    return validateToken(token).get("role", String.class);
  }
}
