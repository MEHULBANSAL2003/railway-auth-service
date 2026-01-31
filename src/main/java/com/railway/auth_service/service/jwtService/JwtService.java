package com.railway.auth_service.service.jwtService;

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

  // ============ ACCESS TOKEN GENERATION ============

  /**
   * Generate access token for USER
   * Claims: userId, email, role=USER, type=USER
   */
  public String generateAccessTokenForUser(Long userId, String email) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("userId", userId);
    claims.put("role", Role.USER.name());
    claims.put("type", "USER");

    return Jwts.builder()
      .setClaims(claims)
      .setSubject(email)
      .setIssuedAt(new Date())
      .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiry))
      .signWith(getSigningKey(), SignatureAlgorithm.HS256)
      .compact();
  }

  /**
   * Generate access token for ADMIN
   * Claims: adminId, email, role=ADMIN/SUPER_ADMIN, type=ADMIN
   */
  public String generateAccessTokenForAdmin(Long adminId, String email, Role adminRole) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("adminId", adminId);
    claims.put("role", adminRole.name());
    claims.put("type", "ADMIN");

    return Jwts.builder()
      .setClaims(claims)
      .setSubject(email)
      .setIssuedAt(new Date())
      .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiry))
      .signWith(getSigningKey(), SignatureAlgorithm.HS256)
      .compact();
  }

  // ============ REFRESH TOKEN GENERATION ============

  /**
   * Generate refresh token (works for both USER and ADMIN)
   * Claims: ownerId, ownerType (USER/ADMIN/SUPER_ADMIN), email
   */
  public String generateRefreshToken(Long ownerId, String email, Role ownerType) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("ownerId", ownerId);
    claims.put("ownerType", ownerType.name());

    return Jwts.builder()
      .setClaims(claims)
      .setSubject(email)
      .setIssuedAt(new Date())
      .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiry))
      .signWith(getSigningKey(), SignatureAlgorithm.HS256)
      .compact();
  }

  // ============ TOKEN VALIDATION ============

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

  // ============ CLAIM EXTRACTION ============

  /**
   * Extract owner ID from refresh token
   */
  public Long extractOwnerId(String token) {
    return validateToken(token).get("ownerId", Long.class);
  }

  /**
   * Extract owner type from refresh token
   */
  public Role extractOwnerType(String token) {
    String type = validateToken(token).get("ownerType", String.class);
    return Role.valueOf(type);
  }

  /**
   * Extract user ID from access token
   */
  public Long extractUserId(String token) {
    return validateToken(token).get("userId", Long.class);
  }

  /**
   * Extract admin ID from access token
   */
  public Long extractAdminId(String token) {
    return validateToken(token).get("adminId", Long.class);
  }

  /**
   * Extract role from token
   */
  public Role extractRole(String token) {
    String role = validateToken(token).get("role", String.class);
    return Role.valueOf(role);
  }

  /**
   * Extract type from access token (USER or ADMIN)
   */
  public String extractType(String token) {
    return validateToken(token).get("type", String.class);
  }

  /**
   * Extract email (subject) from token
   */
  public String extractEmail(String token) {
    return validateToken(token).getSubject();
  }

  /**
   * Check if token is expired
   */
  public boolean isTokenExpired(String token) {
    return validateToken(token).getExpiration().before(new Date());
  }
}
