package com.railway.auth_service.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.security.access.AccessDeniedException;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(BaseException.class)
  public ResponseEntity<ApiErrorResponse> handleBaseException(BaseException ex) {

    ApiError error = new ApiError(
      ex.getCode(),
      ex.getMessage(),
      ex.getDetails()
    );

    return ResponseEntity
      .status(ex.getHttpStatus())
      .body(ApiErrorResponse.error(error));
  }

  // Handle validation errors (@Valid, @NotBlank, etc.)
  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiErrorResponse> handleValidationException(
    MethodArgumentNotValidException ex) {

    // Collect all field errors
    Map<String, String> fieldErrors = new HashMap<>();
    ex.getBindingResult().getFieldErrors().forEach(error ->
      fieldErrors.put(error.getField(), error.getDefaultMessage())
    );

    // Or get the first error message only
    String firstErrorMessage = ex.getBindingResult().getFieldErrors().stream()
      .findFirst()
      .map(error -> error.getDefaultMessage())
      .orElse("Validation failed");

    ApiError error = new ApiError(
      "VALIDATION_ERROR",
      firstErrorMessage,  // Or use a generic message
      fieldErrors  // All field errors as details
    );

    return ResponseEntity
      .status(HttpStatus.BAD_REQUEST)
      .body(ApiErrorResponse.error(error));
  }

  // Handle method not allowed (e.g., POST to GET endpoint)
  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<ApiErrorResponse> handleMethodNotAllowed(
    HttpRequestMethodNotSupportedException ex) {

    String supportedMethods = ex.getSupportedHttpMethods() != null
      ? ex.getSupportedHttpMethods().stream()
      .map(Object::toString)
      .collect(Collectors.joining(", "))
      : "None";

    ApiError error = new ApiError(
      "METHOD_NOT_ALLOWED",
      "HTTP method not supported: " + ex.getMethod(),
      Map.of(
        "supportedMethods", supportedMethods,
        "requestedMethod", ex.getMethod()
      )
    );

    return ResponseEntity
      .status(HttpStatus.METHOD_NOT_ALLOWED)
      .body(ApiErrorResponse.error(error));
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ApiErrorResponse> handleAccessDenied(AccessDeniedException ex) {

    ApiError error = new ApiError(
      "ACCESS_DENIED",
      "You don't have permission to access this resource",
      null
    );

    return ResponseEntity
      .status(HttpStatus.FORBIDDEN)
      .body(ApiErrorResponse.error(error));
  }


  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiErrorResponse> handleUnexpected(Exception ex) {

    ApiError error = new ApiError(
      "INTERNAL_SERVER_ERROR",
      "Something went wrong",
      null
    );

    return ResponseEntity
      .status(HttpStatus.INTERNAL_SERVER_ERROR)
      .body(ApiErrorResponse.error(error));
  }
}
