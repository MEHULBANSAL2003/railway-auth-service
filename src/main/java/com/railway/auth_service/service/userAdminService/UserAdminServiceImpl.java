package com.railway.auth_service.service.userAdminService;

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
public class UserAdminServiceImpl implements UserAdminService {

  private final RefreshTokenService refreshTokenService;

  @Override
  @Transactional
  public LogoutCurrentDeviceResponse logoutFromCurrentDevice(String token) {
    log.info("Processing logout for current device");

    try {
      refreshTokenService.revokeRefreshToken(token);
      log.info("User logged out successfully from current device");

      return LogoutCurrentDeviceResponse.builder()
        .message("Logged out successfully")
        .timestamp(LocalDateTime.now())
        .build();

    } catch (BaseException e) {
      log.error("Logout failed for current device: {}", e.getMessage());
      throw e;
    } catch (Exception e) {
      log.error("Unexpected error during logout from current device", e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "LOGOUT_FAILED", "Failed to logout from current device");
    }
  }

  @Override
  @Transactional
  public LogoutAllDeviceResponse logoutFromAllDevices() {
    Long id = SecurityUtils.getCurrentUserId();
    log.info("Logging out user from all devices: {}", id);

    try {
      refreshTokenService.revokeAllUserTokens(id);
      log.info("User logged out from all devices successfully: {}", id);

      return LogoutAllDeviceResponse.builder()
        .message("Logged out from all devices successfully")
        .timestamp(LocalDateTime.now())
        .build();

    } catch (BaseException e) {
      log.error("Logout failed for all devices for user {}: {}", id, e.getMessage());
      throw e;
    } catch (Exception e) {
      log.error("Unexpected error during logout from all devices for user: {}", id, e);
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "LOGOUT_FAILED", "Failed to logout from all devices");
    }
  }
}
