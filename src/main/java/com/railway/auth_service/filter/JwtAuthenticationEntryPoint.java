package com.railway.auth_service.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.railway.auth_service.exception.ApiError;
import com.railway.auth_service.exception.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

  private final ObjectMapper objectMapper;

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationException authException) throws IOException {

    log.error("Unauthorized access attempt to {}: {}", request.getRequestURI(), authException.getMessage());

    String exceptionType = (String) request.getAttribute("exception");
    String code;
    String message;

    if (exceptionType != null) {
      switch (exceptionType) {
        case "TOKEN_EXPIRED":
          code = "TOKEN_EXPIRED";
          message = "JWT token has expired";
          break;
        case "INVALID_TOKEN":
          code = "INVALID_TOKEN";
          message = "Invalid JWT token format";
          break;
        case "AUTHENTICATION_FAILED":
          code = "AUTHENTICATION_FAILED";
          message = "Authentication failed";
          break;
        default:
          code = "UNAUTHORIZED";
          message = "Authentication required";
      }
    } else {
      code = "UNAUTHORIZED";
      message = "Full authentication is required to access this resource";
    }

    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setCharacterEncoding("UTF-8");

    ApiError error = new ApiError(code, message, null);
    ApiErrorResponse errorResponse = ApiErrorResponse.error(error);

    response.getWriter().write(objectMapper.writeValueAsString(errorResponse));

  }

}
