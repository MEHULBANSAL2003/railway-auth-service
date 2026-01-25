//package com.railway.auth_service.filter;
//
//import com.railway.auth_service.service.jwtService.JwtService;
//import io.jsonwebtoken.ExpiredJwtException;
//import io.jsonwebtoken.MalformedJwtException;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//
//import java.io.IOException;
//import java.util.Collections;
//
//@Slf4j
//@Component
//@RequiredArgsConstructor
//public class JwtAuthenticationFilter extends OncePerRequestFilter {
//
//  private final JwtService jwtService;
//
//  @Override
//  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//    try{
//      String authHeader = request.getHeader("Authorization");
//      if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//        // No token provided
//        // Continue to next filter
//        // If endpoint requires auth, Spring Security will block it
//        log.debug("No JWT token found in request: {}", request.getRequestURI());
//        filterChain.doFilter(request, response);
//        return;
//      }
//      String token = authHeader.substring(7);
//      log.debug("JWT token found for request: {}", request.getRequestURI());
//
//      Long id = jwtService.id(token);        // Extract user ID
//      String role = jwtService.extractRole(token); // Extract role
//
//      log.debug("Token validated - id: {}, role: {}", id, role);
//
//      if (id != null && SecurityContextHolder.getContext().getAuthentication() == null){
//        UsernamePasswordAuthenticationToken authentication =
//          new UsernamePasswordAuthenticationToken(
//            id,  // Principal (who is the user?)
//            null,    // Credentials (password - not needed after login)
//            Collections.singletonList(
//              new SimpleGrantedAuthority(role)  // Authorities (permissions)
//            )
//          );
//
//        // Add request details (IP address, session ID, etc.)
//        authentication.setDetails(
//          new WebAuthenticationDetailsSource().buildDetails(request)
//        );
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        log.debug("User authenticated successfully: id={}, role={}", id, role);
//      }
//
//    }
//    catch (ExpiredJwtException e) {
//      // Token has expired
//      log.error("JWT token expired: {}", e.getMessage());
//      request.setAttribute("exception", "Token expired");
//
//    } catch (MalformedJwtException e) {
//      // Token format is wrong
//      log.error("Malformed JWT token: {}", e.getMessage());
//      request.setAttribute("exception", "Invalid token format");
//
//    } catch (Exception e) {
//      // Any other error
//      log.error("JWT authentication failed: {}", e.getMessage());
//      request.setAttribute("exception", "Authentication failed");
//    }
//
//    filterChain.doFilter(request, response);
//  }
//
//}
