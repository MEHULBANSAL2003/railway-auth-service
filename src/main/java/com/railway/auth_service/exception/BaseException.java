package com.railway.auth_service.exception;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
public class BaseException extends RuntimeException {

  private final String code;
  private final Object details;
  private final HttpStatus httpStatus;

  public BaseException(HttpStatus httpStatus,String code, String message) {
    super(message);
    this.code = code;
    this.details = null;
    this.httpStatus = httpStatus;
  }

  public BaseException(HttpStatus httpStatus,String code, String message, Object details) {
    super(message);
    this.code = code;
    this.details = details;
    this.httpStatus = httpStatus;
  }
}
