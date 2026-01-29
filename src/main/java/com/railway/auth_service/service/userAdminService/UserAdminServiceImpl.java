package com.railway.auth_service.service.userAdminService;

import com.railway.auth_service.dto.request.user.CreateAdminRequest;
import com.railway.auth_service.dto.response.user.AdminUpdateStatusResponse;
import com.railway.auth_service.dto.response.user.CreateAdminResponse;
import com.railway.auth_service.dto.response.user.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.user.LogoutCurrentDeviceResponse;
import com.railway.auth_service.entity.UserEntity;
import com.railway.auth_service.enums.AuthProvider;
import com.railway.auth_service.enums.Role;
import com.railway.auth_service.exception.BaseException;
import com.railway.auth_service.repository.UserAdminRepository;
import com.railway.auth_service.service.refreshTokenService.RefreshTokenService;
import com.railway.auth_service.utils.SecurityUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserAdminServiceImpl implements UserAdminService {

  private final RefreshTokenService refreshTokenService;
  private final UserAdminRepository userAdminRepository;

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

  @Override
  @Transactional
  public AdminUpdateStatusResponse updateUserStatus(Long id, Boolean status) {
    try {
      log.info("Updating user status. userId={}, isActive={}", id, status);
      UserEntity user = userAdminRepository.findById(id)
        .orElseThrow(() ->
          new BaseException(
            HttpStatus.NOT_FOUND,
            "USER_NOT_FOUND",
            "No user found"
          )
        );
      user.setIsActive(status);
      user.setUpdatedAt(LocalDateTime.now());

      userAdminRepository.save(user);

      return AdminUpdateStatusResponse.builder()
        .message("Status upadated Successfully")
        .isActive(status)
        .build();
    }
    catch (BaseException e) {
      log.error("Failed to update user status: {}", e.getMessage());
      throw e;
    }
    catch (Exception e) {
      log.error("Unexpected error while updating user status: {}", e.getMessage());
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "UPDATE_STATUS_FAILED", "Failed to update user status");
    }
  }

  @Override
  @Transactional
  public CreateAdminResponse createAdmin(CreateAdminRequest request){
    try{
      if (userAdminRepository.existsByEmail(request.getEmail())) {
        throw new BaseException(
          HttpStatus.BAD_REQUEST,
          "EMAIL_ALREADY_EXISTS",
          "Email already exists"
        );
      }
      UserEntity user = new UserEntity();
      user.setName(request.getName());
      user.setEmail(request.getEmail());
      user.setUserName(request.getUsername());
      user.setRole(Role.ROLE_ADMIN);
      user.setIsActive(true);
      user.setAuthProvider(AuthProvider.GOOGLE);
      userAdminRepository.save(user);

      return CreateAdminResponse.builder()
        .id(user.getId())
        .email(user.getEmail())
        .name(user.getName())
        .userName(user.getUserName())
        .build();
    }
    catch(BaseException e){
      log.error("Failed to create admin: {}", e.getMessage());
      throw e;
    }
    catch(Exception e){
      log.error("Unexpected error while creating admin: {}", e.getMessage());
      throw new BaseException(HttpStatus.INTERNAL_SERVER_ERROR, "CREATE_ADMIN_FAILED", "Failed to create admin");
    }
  }
}
