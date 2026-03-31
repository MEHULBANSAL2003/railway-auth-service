package com.railway.auth_service.service.impl;

import com.railway.auth_service.dto.request.CreateAdminRequest;
import com.railway.auth_service.dto.response.AdminResponse;
import com.railway.auth_service.dto.response.AdminUserDetailResponse;
import com.railway.auth_service.dto.response.CreateAdminResponse;
import com.railway.auth_service.mapper.AdminMapper;
import com.railway.auth_service.mapper.UserMapper;
import com.railway.auth_service.model.entity.Admin;
import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.enums.AdminRole;
import com.railway.auth_service.repository.AdminRepository;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.auth_service.service.AdminService;
import com.railway.common.dto.PagedResponse;
import com.railway.common.exception.BadRequestException;
import com.railway.common.exception.ConflictException;
import com.railway.common.exception.ForbiddenException;
import com.railway.common.exception.ResourceNotFoundException;
import com.railway.common.security.TokenBlacklistService;
import com.railway.common.specification.GenericSpecification;
import com.railway.common.util.PaginationUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

  private final AdminRepository adminRepository;
  private final AdminMapper adminMapper;
  private final Optional<TokenBlacklistService> blacklistService;
  private final RefreshTokenRepository refreshTokenRepository;
  private final UserRepository userRepository;
  private final UserMapper userMapper;

  private static final String[] ALLOWED_SORT_FIELDS = {
    "createdAt", "email", "firstName", "department", "role", "lastLoginAt"
  };

  @Value("${app.jwt.access-token-expiry}")
  private long accessTokenExpiry;

  @Override
  @Transactional
  public CreateAdminResponse createAdmin(CreateAdminRequest request, Long createdBy) {

    // Only ADMIN role can be created via API — no SUPER_ADMIN creation
    if (request.getRole() == AdminRole.SUPER_ADMIN) {
      throw new ForbiddenException("SUPER_ADMIN cannot be created via API");
    }

    // Check email uniqueness
    if (adminRepository.existsByEmail(request.getEmail().toLowerCase().trim())) {
      throw new ConflictException("Admin with email " + request.getEmail() + " already exists");
    }

    // Check phone uniqueness
    if (adminRepository.existsByPhone(request.getPhone().trim())) {
      throw new ConflictException("Admin with phone " + request.getPhone() + " already exists");
    }

    // Build entity
    Admin admin = Admin.builder()
      .email(request.getEmail().toLowerCase().trim())
      .firstName(request.getFirstName().trim())
      .lastName(request.getLastName() != null ? request.getLastName().trim() : null)
      .phone(request.getPhone().trim())
      .department(request.getDepartment())
      .role(request.getRole())
      .createdBy(createdBy)
      .build();

    try {
      Admin saved = adminRepository.save(admin);
      log.info("Admin created: id={}, email={}, role={}, by={}",
        saved.getAdminId(), saved.getEmail(), saved.getRole(), createdBy);
      return adminMapper.toCreateResponse(saved);
    } catch (DataIntegrityViolationException ex) {
      log.error("Data integrity violation creating admin: {}", ex.getMessage());
      throw new ConflictException("Admin with this email or phone already exists");
    }
  }

  @Override
  @Transactional
  public Map<String, Object> changeRole(Long adminId, Long requestedBy) {

    // Can't change your own role
    if (adminId.equals(requestedBy)) {
      throw new BadRequestException("You cannot change your own role");
    }

    Admin admin = adminRepository.findById(adminId)
      .orElseThrow(() -> new ResourceNotFoundException("Admin", "adminId", adminId));

    // Toggle role: ADMIN ↔ SUPER_ADMIN
    AdminRole oldRole = admin.getRole();
    AdminRole newRole = (oldRole == AdminRole.ADMIN) ? AdminRole.SUPER_ADMIN : AdminRole.ADMIN;

    admin.setRole(newRole);
    adminRepository.save(admin);

    // Revoke sessions — force re-login so the new JWT has the updated role
    refreshTokenRepository.revokeAllByOwner(adminId, "admin");
    blacklistService.ifPresent(service ->
      service.setCutoff("admin", adminId, Duration.ofMillis(accessTokenExpiry))
    );

    log.info("Admin role changed: id={}, {} → {}, by={}", adminId, oldRole, newRole, requestedBy);

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("message", "Role changed successfully");
    result.put("adminId", admin.getAdminId());
    result.put("email", admin.getEmail());
    result.put("previousRole", oldRole.name());
    result.put("newRole", newRole.name());
    return result;
  }

  @Override
  @Transactional
  public Map<String, Object> toggleStatus(Long adminId, Long requestedBy) {

    // Can't toggle your own status
    if (adminId.equals(requestedBy)) {
      throw new BadRequestException("You cannot change your own status");
    }

    Admin admin = adminRepository.findById(adminId)
      .orElseThrow(() -> new ResourceNotFoundException("Admin", "adminId", adminId));

    // Toggle
    boolean newStatus = !admin.isEnabled();
    admin.setEnabled(newStatus);
    adminRepository.save(admin);

    // If disabled → revoke all sessions immediately
    if (!newStatus) {
      refreshTokenRepository.revokeAllByOwner(adminId, "admin");
      blacklistService.ifPresent(service ->
        service.setCutoff("admin", adminId, Duration.ofMillis(accessTokenExpiry))
      );
      log.info("Admin disabled and sessions revoked: id={}, by={}", adminId, requestedBy);
    } else {
      log.info("Admin enabled: id={}, by={}", adminId, requestedBy);
    }

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("message", newStatus ? "Admin enabled successfully" : "Admin disabled successfully");
    result.put("adminId", admin.getAdminId());
    result.put("email", admin.getEmail());
    result.put("enabled", newStatus);
    return result;
  }

  @Override
  @Transactional(readOnly = true)
  public AdminResponse getAdminById(Long adminId) {
    Admin admin = adminRepository.findById(adminId)
      .orElseThrow(() -> new ResourceNotFoundException("Admin", "adminId", adminId));
    return adminMapper.toResponse(admin);
  }

  /**
   * Get own profile. Same as getAdminById but semantically different —
   * any admin can call this, not just SUPER_ADMIN.
   */
  @Override
  @Transactional(readOnly = true)
  public AdminResponse getOwnProfile(Long adminId) {
    Admin admin = adminRepository.findById(adminId)
      .orElseThrow(() -> new ResourceNotFoundException("Admin", "adminId", adminId));
    return adminMapper.toResponse(admin);
  }

  /**
   * List admins with pagination, sorting, and filtering.
   *
   * Admin panel sees everything (active + inactive).
   * No activeOnly filter — admins need the full picture.
   *
   * Filters are all optional — null values are ignored.
   * ?role=ADMIN → only ADMINs
   * ?department=OPERATIONS&search=priya → OPERATIONS dept, name/email contains "priya"
   * no params → all admins, sorted by createdAt desc
   */
  @Override
  @Transactional(readOnly = true)
  public PagedResponse<AdminResponse> listAdmins(Integer page, Integer size,
                                                 String sortBy, String sortDir,
                                                 String role, String department,
                                                 Boolean enabled, String searchName,
                                                 String searchEmail, String searchPhone,
                                                 String search) {

    Pageable pageable = PaginationUtil.buildPageable(page, size, sortBy, sortDir, ALLOWED_SORT_FIELDS);

    Specification<Admin> spec = GenericSpecification.<Admin>builder()
      // Exact match filters (dropdowns in frontend)
      .equal("role", role)
      .equal("department", department)
      .isTrue("enabled", enabled)
      // Column-specific LIKE filters (per-column search in data table)
      .like("firstName", searchName)
      .like("email", searchEmail)
      .like("phone", searchPhone)
      // Global search (search bar — across all text fields)
      .search(search, "email", "firstName", "lastName", "phone")
      .build();

    Page<Admin> adminPage = adminRepository.findAll(spec, pageable);

    return PagedResponse.of(adminPage, adminMapper::toResponse);
  }

  @Override
  public AdminUserDetailResponse getUserById(Long userId) {

    User user = userRepository.findById(userId)
      .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

    return userMapper.toAdminDetailResponse(user);
  }


}
