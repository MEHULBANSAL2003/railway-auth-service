package com.railway.auth_service.exception;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class BaseException extends RuntimeException {

  private final String code;
  private final Object details;

  public BaseException(String code, String message) {
    super(message);
    this.code = code;
    this.details = null;
  }

  public BaseException(String code, String message, Object details) {
    super(message);
    this.code = code;
    this.details = details;
  }
}
