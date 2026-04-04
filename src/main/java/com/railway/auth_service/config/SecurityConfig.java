package com.railway.auth_service.config;

import com.railway.common.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * Spring Security configuration for auth-service.
 *
 * EACH SERVICE has its own SecurityConfig because each service
 * has different public/protected endpoints. But they all use
 * the same JwtAuthFilter from common-lib.
 *
 * WHY @EnableMethodSecurity?
 *   Enables @PreAuthorize annotations on controller methods.
 *   Example: @PreAuthorize("hasRole('SUPER_ADMIN')")
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final JwtAuthenticationFilter jwtAuthFilter;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

    http
      // Disable Spring Security's CORS processing — handled by
      // our standalone CorsFilter registered at highest precedence.
      .cors(AbstractHttpConfigurer::disable)

      // Disable CSRF — we're a stateless REST API using JWT,
      // not a server-rendered form-based app.
      .csrf(AbstractHttpConfigurer::disable)

      // Stateless sessions — no server-side sessions.
      // Every request is authenticated independently via JWT.
      .sessionManagement(session ->
        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      )

      // Endpoint access rules
      .authorizeHttpRequests(auth -> auth

        // Public endpoints — no token needed
        .requestMatchers(
          "/api/auth/**",
          "/actuator/**"
        ).permitAll()

        // Admin endpoints — require authentication
        .requestMatchers("/api/admin/**").authenticated()
        .requestMatchers("/api/user/**").authenticated()

        // Everything else requires authentication
        .anyRequest().authenticated()
      )

      // Add our JWT filter BEFORE Spring's default auth filter
      .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  /**
   * Standalone CORS filter registered at HIGHEST_PRECEDENCE.
   *
   * WHY not use Spring Security's .cors()?
   *   Spring Security's built-in CORS runs inside the security filter chain.
   *   If any security filter rejects the request (401/403) before CORS
   *   headers are added, the browser sees a response without CORS headers
   *   and reports "CORS error" instead of the actual 401/403.
   *
   *   By registering CorsFilter as a servlet filter at highest precedence,
   *   it runs BEFORE the entire Spring Security chain. CORS headers are
   *   always added — even on error responses.
   */
  @Bean
  public FilterRegistrationBean<CorsFilter> corsFilterRegistration() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("http://localhost:3000","http://localhost:5173","https://railtick.in","https://admin.railtick.in", "https://dev.railtick.in", "https://dev.admin.railtick.in" ));
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("*"));
    config.setAllowCredentials(true);
    config.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);

    FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
    return bean;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
