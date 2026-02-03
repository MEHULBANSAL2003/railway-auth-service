package com.railway.auth_service.config.securityConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.railway.auth_service.constants.ApiConstants;

import com.railway.common.exceptions.ApiError;
import com.railway.common.exceptions.ApiErrorResponse;
import com.railway.common.security.JwtAuthenticationEntryPoint;
import com.railway.common.security.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

    http
      .cors(cors -> cors.configurationSource(corsConfigurationSource()))
      .csrf(AbstractHttpConfigurer::disable)
      .authorizeHttpRequests(auth -> auth
        .requestMatchers(ApiConstants.AUTH_BASE + "/**").permitAll()
        .requestMatchers("/actuator/health").permitAll()
        .requestMatchers("/actuator/prometheus").permitAll()
        .requestMatchers("/error").permitAll()
        .requestMatchers("/api/**").authenticated()
        .anyRequest().authenticated()

      )
      .exceptionHandling(exception -> exception
        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
        .accessDeniedHandler(accessDeniedHandler())
      )
      .sessionManagement(session -> session
        .sessionCreationPolicy(
          SessionCreationPolicy.STATELESS)
      )
      .addFilterBefore(
        jwtAuthenticationFilter,
        UsernamePasswordAuthenticationFilter.class
      );

    return http.build();

  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    // Allow credentials
    configuration.setAllowCredentials(true);

    // Allowed origins
    configuration.setAllowedOrigins(Arrays.asList(
      "http://localhost:5173",
      "http://localhost:3000",
      "http://127.0.0.1:5173"
    ));

    // Allowed headers
    configuration.setAllowedHeaders(Arrays.asList("*"));

    // Allowed methods
    configuration.setAllowedMethods(Arrays.asList(
      "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
    ));

    // Expose headers to frontend
    configuration.setExposedHeaders(Arrays.asList(
      "Authorization",
      "Content-Type"
    ));

    // Cache preflight for 1 hour
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);

    return source;
  }

  @Bean
  public AccessDeniedHandler accessDeniedHandler() {
    return (request, response, accessDeniedException) -> {
      log.error("Access denied to {}: {}", request.getRequestURI(), accessDeniedException.getMessage());

      response.setStatus(HttpStatus.FORBIDDEN.value());
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      response.setCharacterEncoding("UTF-8");

      ApiError error = new ApiError(
        "ACCESS_DENIED",
        "You don't have permission to access this resource",
        null
      );
      ApiErrorResponse errorResponse = ApiErrorResponse.error(error);

      ObjectMapper mapper = new ObjectMapper();
      response.getWriter().write(mapper.writeValueAsString(errorResponse));
    };
  };

}
