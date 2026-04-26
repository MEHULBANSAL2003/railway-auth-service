package com.railway.auth_service.mapper;

import com.railway.auth_service.dto.response.AdminUserDetailResponse;
import com.railway.auth_service.dto.response.LastLoginMetadata;
import com.railway.auth_service.dto.response.RegistrationMetadata;
import com.railway.auth_service.dto.response.UserProfileResponse;
import com.railway.auth_service.model.entity.User;
import org.springframework.stereotype.Component;

/**
 * Maps User entity to response DTOs.
 *
 * Why a mapper class instead of building in the service?
 * Single Responsibility — mapping is its own concern.
 * Same mapping might be needed in multiple services
 * (UserService, AdminService). DRY.
 *
 * Consistent with AdminMapper pattern you already have.
 */
@Component
public class UserMapper {

  /**
   * Maps User entity to user's own profile view.
   * Used by: GET /api/user/me, login response, registration response.
   */
  public UserProfileResponse toProfileResponse(User user) {
    return UserProfileResponse.builder()
      .userId(user.getUserId())
      .username(user.getUsername())
      .fullName(user.getFullName())
      .email(user.getEmail())
      .countryCode(user.getCountryCode())
      .phone(user.getPhone())
      .phoneVerified(user.isPhoneVerified())
      .emailVerified(user.isEmailVerified())
      .profileImageUrl(user.getProfileImageUrl())
      .dateOfBirth(user.getDateOfBirth())
      .gender(user.getGender())
      .createdAt(user.getCreatedAt())
      .build();
  }


  public AdminUserDetailResponse toAdminDetailResponse(User user) {
    // Build registration metadata
    RegistrationMetadata registrationMetadata = RegistrationMetadata.builder()
      .registeredAt(user.getRegisteredAt())
      .registeredIp(user.getRegisteredIp())
      .deviceType(user.getRegisteredDeviceType())
      .deviceName(user.getRegisteredDeviceName())
      .os(user.getRegisteredOs())
      .browser(user.getRegisteredBrowser())
      .city(user.getRegisteredCity())
      .state(user.getRegisteredState())
      .country(user.getRegisteredCountry())
      .latitude(user.getRegisteredLatitude())
      .longitude(user.getRegisteredLongitude())
      .build();

    // Build last login metadata
    LastLoginMetadata lastLoginMetadata = LastLoginMetadata.builder()
      .lastLoginAt(user.getLastLoginAt())
      .lastLoginIp(user.getLastLoginIp())
      .deviceType(user.getLastDeviceType())
      .deviceName(user.getLastDeviceName())
      .os(user.getLastOs())
      .browser(user.getLastBrowser())
      .city(user.getLastLoginCity())
      .state(user.getLastLoginState())
      .country(user.getLastLoginCountry())
      .latitude(user.getLastLoginLatitude())
      .longitude(user.getLastLoginLongitude())
      .build();

    return AdminUserDetailResponse.builder()
      .userId(user.getUserId())
      .username(user.getUsername())
      .fullName(user.getFullName())
      .email(user.getEmail())
      .countryCode(user.getCountryCode())
      .phone(user.getPhone())
      .phoneVerified(user.isPhoneVerified())
      .emailVerified(user.isEmailVerified())
      .status(user.getStatus())
      .statusReason(user.getStatusReason())
      .registrationMetadata(registrationMetadata)
      .lastLoginMetadata(lastLoginMetadata)
      .profileImageUrl(user.getProfileImageUrl())
      .dateOfBirth(user.getDateOfBirth())
      .gender(user.getGender())
      .passwordChangeCount(user.getPasswordChangeCount())
      .lastPasswordChangeAt(user.getLastPasswordChangeAt())
      .createdAt(user.getCreatedAt())
      .updatedAt(user.getUpdatedAt())
      .deletedAt(user.getDeletedAt())
      .deletionScheduledAt(user.getDeletionScheduledAt())
      .deletionReason(user.getDeletionReason())
      .build();
  }
}
