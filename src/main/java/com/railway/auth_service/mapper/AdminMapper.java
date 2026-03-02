package com.railway.auth_service.mapper;

import com.railway.auth_service.dto.response.admin.AdminSummaryResponse;
import com.railway.auth_service.entity.AdminEntity;
import com.railway.common.security.SecurityUtils;

/**
 * Stateless mapper for AdminEntity conversions.
 * Static methods — no need for @Component since there's no Spring dependency.
 */
public final class AdminMapper {

  private AdminMapper() {}

  /**
   * Convert an {@link AdminEntity} to a lean {@link AdminSummaryResponse}
   * suitable for list endpoints.
   */
  public static AdminSummaryResponse toSummary(AdminEntity admin) {
    boolean isSuperAdmin = SecurityUtils.isSuperAdmin();

    return AdminSummaryResponse.builder()
      .id(admin.getId())
      .fullName(admin.getFullName())
      .email(admin.getEmail())
      .countryCode(admin.getCountryCode())
      .phoneNumber(admin.getPhoneNumber())
      .adminRole(admin.getAdminRole())
      .department(admin.getDepartment())
      .isActive(admin.getIsActive())
      .profilePictureUrl(admin.getProfilePictureUrl())
      .lastLoginAt(admin.getLastLoginAt())
      .createdAt(admin.getCreatedAt())
      .canUpdatedByCurrentAdmin(isSuperAdmin)
      .canDeletedByCurrentAdmin(isSuperAdmin)
      .build();
  }
}
