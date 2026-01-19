package com.railway.auth_service.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ApiErrorResponse {
  private String status;
  private ApiError error;

  public static ApiErrorResponse error(ApiError error) {
    return new ApiErrorResponse("error", error);
  }
}
