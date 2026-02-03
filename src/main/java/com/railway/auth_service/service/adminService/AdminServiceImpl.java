package com.railway.auth_service.service.adminService;


import com.railway.auth_service.dto.request.admin.CreateAdminRequest;
import com.railway.auth_service.dto.request.admin.LogoutCurrentDeviceRequest;
import com.railway.auth_service.dto.response.admin.CreateAdminResponse;
import com.railway.auth_service.dto.response.admin.LogoutAllDeviceResponse;
import com.railway.auth_service.dto.response.admin.LogoutCurrentDeviceResponse;
import com.railway.auth_service.entity.AdminEntity;
import com.railway.auth_service.entity.RefreshTokenEntity;
import com.railway.common.enums.Role;
import com.railway.common.exceptions.BaseException;
import com.railway.auth_service.repository.AdminRepository;
import com.railway.auth_service.service.refreshTokenService.RefreshTokenService;
import com.railway.common.logging.Loggable;
import com.railway.common.security.SecurityUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
@Loggable
public class AdminServiceImpl implements AdminService{

  private final AdminRepository adminRepository;
  private final RefreshTokenService refreshTokenService;

  @Override
  @Transactional
  public LogoutCurrentDeviceResponse logoutCurrentDevice(LogoutCurrentDeviceRequest request) {
    log.info("=== Starting Logout Current Device Flow ===");

    try{

      RefreshTokenEntity refreshToken = refreshTokenService.verifyRefreshToken(request.getRefreshToken());

      Long ownerId = refreshToken.getOwnerId();
      Role ownerType = refreshToken.getOwnerType();
      String deviceInfo = refreshToken.getDeviceInfo();
      String ipAddress = refreshToken.getIpAddress();
      LocalDateTime lastUsedAt = refreshToken.getLastUsedAt();

      log.info("Refresh token verified for {}: {}", ownerType, ownerId);

     // String email = getEmailByOwnerIdAndType(ownerId, ownerType);

      refreshTokenService.revokeRefreshToken(request.getRefreshToken());
      log.info("Refresh token revoked successfully for {}: {}", ownerType, ownerId);

      LogoutCurrentDeviceResponse response = LogoutCurrentDeviceResponse.builder()
        .message("Logged out successfully from current device")
        .timestamp(LocalDateTime.now())
        .ownerType(ownerType.name())
        .ownerId(ownerId)
        .deviceInfo(deviceInfo)
        .ipAddress(ipAddress)
        .lastUsedAt(lastUsedAt)
        .build();

      log.info("=== Logout Current Device Completed Successfully ===");

      return response;

    }
    catch (BaseException e) {
      log.error("Logout current device failed: {}", e.getMessage());
      throw e;
    } catch (Exception e) {
      log.error("Unexpected error during logout current device", e);
      throw new BaseException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "LOGOUT_FAILED",
        "Failed to logout. Please try again."
      );
    }

  }

  @Override
  @Transactional
  public LogoutAllDeviceResponse logoutAllDevices() {
    log.info("=== Starting Logout All Devices Flow ===");
    Long ownerId = SecurityUtils.getCurrentId();
    String ownerType = SecurityUtils.getCurrentRole();
    Role role = Role.valueOf(ownerType);

    log.debug("Owner validated: {}: {}", ownerType, ownerId);

    log.debug("Step 2: Getting count of active sessions");

    List<RefreshTokenEntity> activeSessions = refreshTokenService.getActiveSessions(
      ownerId,
      role
    );

    int sessionCount = activeSessions.size();

    log.info("Found {} active sessions for {}: {}", sessionCount, ownerType, ownerId);

    // ========== STEP 3: REVOKE ALL TOKENS ==========
    log.debug("Step 3: Revoking all refresh tokens");

    refreshTokenService.revokeAllTokens(ownerId, role);

    log.info("All tokens revoked successfully for {}: {}", ownerType, ownerId);

    LogoutAllDeviceResponse response = LogoutAllDeviceResponse.builder()
      .message("Logged out successfully from all devices")
      .timestamp(LocalDateTime.now())
      .ownerType(ownerType)
      .ownerId(ownerId)
      .devicesLoggedOut(sessionCount)
      .build();

    log.info("=== Logout All Devices Completed Successfully ===");
    return response;
  }

  @Override
  @Transactional
  public CreateAdminResponse createNewAdmin(CreateAdminRequest request) {

    if(adminRepository.existsByEmailOrPhone(request.getEmail(), request.getPhoneNumber())){
      throw new BaseException(HttpStatus.CONFLICT, "ADMIN_ALREADY_EXISTS", "Admin with email already exists");
    }

    AdminEntity adminEntity = AdminEntity.builder()
      .department(request.getDepartment())
      .email(request.getEmail())
      .fullName(request.getFullName())
      .adminRole(request.getRole())
      .phoneNumber(request.getPhoneNumber())
      .createdBy(SecurityUtils.getCurrentAdminId())
      .build();

    AdminEntity adminData = adminRepository.save(adminEntity);
    log.info("Admin created successfully: {}", request.getEmail());

    return CreateAdminResponse.builder()
      .email(adminData.getEmail())
      .id(adminData.getId())
      .name(adminData.getFullName())
      .department(adminData.getDepartment())
      .adminRole(adminData.getAdminRole())
      .createdAt(adminData.getCreatedAt())
      .build();
  }

}
