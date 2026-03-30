package com.railway.auth_service.mapper;

import com.railway.auth_service.dto.response.AdminProfileResponse;
import com.railway.auth_service.dto.response.AdminResponse;
import com.railway.auth_service.dto.response.AuthResponse;
import com.railway.auth_service.dto.response.CreateAdminResponse;
import com.railway.auth_service.model.entity.Admin;
import org.springframework.stereotype.Component;

/**
 * Converts Admin entity ↔ DTOs.
 *
 * WHY a separate mapper class?
 *   Without it, conversion logic lives in the service or controller:
 *     AdminResponse response = new AdminResponse();
 *     response.setAdminId(admin.getAdminId());
 *     response.setEmail(admin.getEmail());
 *     ... 15 more lines
 *
 *   Repeated everywhere you return an admin. DRY violation.
 *   Mapper centralizes it — one place to change if a field is
 *   added or the response format changes.
 *
 * WHY not MapStruct?
 *   MapStruct generates mapper implementations at compile time
 *   using annotations. It's great for large projects with many
 *   entities. For our scale, a hand-written mapper is simpler
 *   and easier to understand. We can migrate to MapStruct later
 *   if the boilerplate grows. KISS.
 */
@Component
public class AdminMapper {

  public AdminResponse toResponse(Admin admin) {
    return AdminResponse.builder()
      .adminId(admin.getAdminId())
      .email(admin.getEmail())
      .firstName(admin.getFirstName())
      .lastName(admin.getLastName())
      .profileImageUrl(admin.getProfileImageUrl())
      .countryCode(admin.getCountryCode())
      .phone(admin.getPhone())
      .department(admin.getDepartment())
      .role(admin.getRole())
      .emailVerified(admin.isEmailVerified())
      .enabled(admin.isEnabled())
      .lastLoginAt(admin.getLastLoginAt())
      .createdAt(admin.getCreatedAt())
      .createdBy(admin.getCreatedBy())
      .build();
  }

  public AdminProfileResponse toProfileResponse(Admin admin) {
    return AdminProfileResponse.builder()
      .adminId(admin.getAdminId())
      .email(admin.getEmail())
      .firstName(admin.getFirstName())
      .lastName(admin.getLastName())
      .profileImageUrl(admin.getProfileImageUrl())
      .countryCode(admin.getCountryCode())
      .phone(admin.getPhone())
      .department(admin.getDepartment().name())
      .role(admin.getRole().name())
      .emailVerified(admin.isEmailVerified())
      .build();    // ← this was missing
  }


  public CreateAdminResponse toCreateResponse(Admin admin) {
    return CreateAdminResponse.builder()
      .message("Admin created successfully")
      .admin(CreateAdminResponse.AdminDetails.builder()
        .adminId(admin.getAdminId())
        .email(admin.getEmail())
        .firstName(admin.getFirstName())
        .lastName(admin.getLastName())
        .countryCode(admin.getCountryCode())
        .phone(admin.getPhone())
        .department(admin.getDepartment().name())
        .role(admin.getRole().name())
        .emailVerified(admin.isEmailVerified())
        .enabled(admin.isEnabled())
        .build())
      .build();
  }
}
