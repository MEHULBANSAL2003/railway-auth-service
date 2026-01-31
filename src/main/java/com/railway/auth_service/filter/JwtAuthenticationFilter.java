package com.railway.auth_service.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.railway.auth_service.exception.ApiError;
import com.railway.auth_service.exception.ApiErrorResponse;
import com.railway.auth_service.security.JwtAuthenticationPrincipal;
import com.railway.auth_service.service.jwtService.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * JWT Authentication Filter
 *
 * This filter extracts and validates JWT tokens from requests.
 * It sets up Spring Security authentication context based on token type (USER or ADMIN).
 *
 * Token Structure:
 * - USER tokens contain: userId, role=USER, type=USER
 * - ADMIN tokens contain: adminId, role=ADMIN/SUPER_ADMIN, type=ADMIN
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  protected void doFilterInternal(
    HttpServletRequest request,
    HttpServletResponse response,
    FilterChain filterChain
  ) throws ServletException, IOException {

    try {
      // ========== STEP 1: EXTRACT TOKEN ==========
      String authHeader = request.getHeader("Authorization");

      if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        log.debug("No JWT token found in request: {}", request.getRequestURI());
        filterChain.doFilter(request, response);
        return;
      }

      String token = authHeader.substring(7);
      log.debug("JWT token found for request: {}", request.getRequestURI());

      // ========== STEP 2: VALIDATE TOKEN & EXTRACT CLAIMS ==========
      // This will throw exception if token is invalid/expired
      String tokenType = jwtService.extractType(token);  // "USER" or "ADMIN"
      String email = jwtService.extractEmail(token);

      log.debug("Token type: {}, email: {}", tokenType, email);

      // ========== STEP 3: EXTRACT USER/ADMIN ID & ROLE BASED ON TYPE ==========
      Long principalId;
      String role;

      if ("USER".equals(tokenType)) {
        // Extract user-specific claims
        principalId = jwtService.extractUserId(token);
        role = jwtService.extractRole(token).name();  // Should be "USER"

        log.debug("User token validated - userId: {}, role: {}", principalId, role);

      } else if ("ADMIN".equals(tokenType)) {
        // Extract admin-specific claims
        principalId = jwtService.extractAdminId(token);
        role = jwtService.extractRole(token).name();  // "ADMIN" or "SUPER_ADMIN"

        log.debug("Admin token validated - adminId: {}, role: {}", principalId, role);

      } else {
        log.error("Unknown token type: {}", tokenType);
        handleAuthenticationError(response, "INVALID_TOKEN", "Unknown token type");
        return;
      }

      // ========== STEP 4: SET SECURITY CONTEXT ==========
      if (principalId != null && SecurityContextHolder.getContext().getAuthentication() == null) {

        // Create custom principal object containing all token info
        JwtAuthenticationPrincipal principal = new JwtAuthenticationPrincipal(
          principalId,
          email,
          tokenType,
          role
        );

        // Create authorities list
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));

        // For admins, also add general ADMIN authority
        if ("ADMIN".equals(tokenType)) {
          authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }

        // Create authentication token
        UsernamePasswordAuthenticationToken authentication =
          new UsernamePasswordAuthenticationToken(
            principal,           // Principal (contains all user/admin info)
            null,               // Credentials (not needed after authentication)
            authorities         // Authorities (permissions)
          );

        // Add request details (IP address, session ID, etc.)
        authentication.setDetails(
          new WebAuthenticationDetailsSource().buildDetails(request)
        );

        // Set in security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.debug("Authentication set successfully - type: {}, id: {}, role: {}",
          tokenType, principalId, role);
      }

      // Continue to next filter
      filterChain.doFilter(request, response);

    } catch (ExpiredJwtException e) {
      log.error("JWT token expired: {}", e.getMessage());
      handleAuthenticationError(response, "TOKEN_EXPIRED", "JWT token has expired. Please login again.");

    } catch (MalformedJwtException e) {
      log.error("Malformed JWT token: {}", e.getMessage());
      handleAuthenticationError(response, "INVALID_TOKEN", "Invalid JWT token format");

    } catch (Exception e) {
      log.error("JWT authentication failed: {}", e.getMessage(), e);
      handleAuthenticationError(response, "AUTHENTICATION_FAILED", "Authentication failed. Please login again.");
    }
  }

  /**
   * Handle authentication errors by sending JSON error response
   */
  private void handleAuthenticationError(
    HttpServletResponse response,
    String code,
    String message
  ) throws IOException {
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setCharacterEncoding("UTF-8");

    ApiError error = new ApiError(code, message, null);
    ApiErrorResponse errorResponse = ApiErrorResponse.error(error);

    response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
  }
}
