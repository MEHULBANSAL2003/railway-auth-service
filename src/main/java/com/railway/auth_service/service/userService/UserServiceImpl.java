package com.railway.auth_service.service.userService;

import com.railway.auth_service.dto.response.user.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.user.LogoutCurrentDeviceResponse;
import com.railway.auth_service.exception.BaseException;
import com.railway.auth_service.service.refreshTokenService.RefreshTokenService;
import com.railway.auth_service.utils.SecurityUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

  private final RefreshTokenService refreshTokenService;


  @Override
  @Transactional
  public LogoutCurrentDeviceResponse logoutFromCurrentDevice(String token) {
    log.info("Processing logout");
    try {
      refreshTokenService.revokeRefreshToken(token);
      log.info("User logged out successfully");
      return LogoutCurrentDeviceResponse.builder()
          .message("Logged out successfully")
          .timestamp(LocalDateTime.now())
        .build();
    } catch (BaseException e) {
      log.error("Logout failed", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "AUTH_ERROR",
        "Authentication failed. Please try again."
      );
    }

  }


  @Override
  public LogoutAllDeviceResponse logoutFromAllDevices() {
    Long id = SecurityUtils.getCurrentUserId();
    log.info("Logging out user from all devices: {}", id);
    try {
      refreshTokenService.revokeAllUserTokens(id);
      log.info("User logged out from all devices: {}", id);

      return LogoutAllDeviceResponse.builder()
        .message("Logged out from all devices successfully")
        .timestamp(LocalDateTime.now())
        .build();
    }
    catch (BaseException e){
      log.error("Logout failed", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "AUTH_ERROR",
        "Authentication failed. Please try again."
      );
    }
  }
}
