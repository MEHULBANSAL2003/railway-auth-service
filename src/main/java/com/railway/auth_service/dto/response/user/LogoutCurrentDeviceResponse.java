package com.railway.auth_service.dto.response.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogoutCurrentDeviceResponse {

  String message;
  LocalDateTime timestamp;
}
