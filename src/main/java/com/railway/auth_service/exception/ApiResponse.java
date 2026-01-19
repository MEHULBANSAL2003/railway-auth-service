package com.railway.auth_service.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ApiResponse<T> {
  private String status;
  private T data;

  public static <T> ApiResponse<T> success(T data) {
    return new ApiResponse<>("success", data);
  }
}
