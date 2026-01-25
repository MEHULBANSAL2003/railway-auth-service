package com.railway.auth_service.config.securityConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.railway.auth_service.constants.ApiConstants;
import com.railway.auth_service.exception.ApiError;
import com.railway.auth_service.exception.ApiErrorResponse;
import com.railway.auth_service.filter.JwtAuthenticationEntryPoint;
import com.railway.auth_service.filter.JwtAuthenticationFilter;
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
