package com.railway.auth_service.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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
      .badRequest()
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

