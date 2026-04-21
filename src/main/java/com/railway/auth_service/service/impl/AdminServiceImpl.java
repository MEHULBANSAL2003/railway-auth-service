package com.railway.auth_service.service.impl;

import com.railway.auth_service.dto.request.CreateAdminRequest;
import com.railway.auth_service.dto.response.ActiveSessionResponse;
import com.railway.auth_service.dto.response.AdminResponse;
import com.railway.auth_service.dto.response.AdminUserDetailResponse;
import com.railway.auth_service.dto.response.CreateAdminResponse;
import com.railway.auth_service.dto.response.UserStatusHistoryResponse;
import com.railway.auth_service.dto.response.UsersAnalyticsDataResponse;
import com.railway.auth_service.mapper.AdminMapper;
import com.railway.auth_service.mapper.UserMapper;
import com.railway.auth_service.model.entity.Admin;
import com.railway.auth_service.model.entity.RefreshToken;
import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.entity.UserStatusHistory;
import com.railway.auth_service.model.enums.ActorType;
import com.railway.auth_service.model.enums.AdminRole;
import com.railway.auth_service.model.enums.UserStatus;
import com.railway.auth_service.repository.AdminRepository;
import com.railway.auth_service.repository.RefreshTokenRepository;
import com.railway.auth_service.repository.UserRepository;
import com.railway.auth_service.repository.UserStatusHistoryRepository;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
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
  private final UserStatusHistoryRepository statusHistoryRepository;

  private static final String[] ALLOWED_SORT_FIELDS = {
    "createdAt", "email", "firstName", "department", "role", "lastLoginAt"
  };

  private static final String[] ALLOWED_HISTORY_SORT_FIELDS = {
    "changedAt", "userId", "oldStatus", "newStatus", "changedById"
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

  /**
   * Get status history for a specific user with pagination, sorting, and optional filtering by adminId.
   *
   * Efficient query design:
   * - Uses indexed columns (user_id, changed_at, changed_by_id)
   * - LEFT JOIN FETCH prevents N+1 queries by eagerly loading user data
   * - Pagination limits memory usage for large result sets
   * - Optional adminId filter to see changes made by specific admin
   *
   * Use cases:
   * - View status change timeline on user profile page
   * - Track who changed user status and when
   * - Filter to see changes made by specific admin
   * - Audit trail for specific user
   */
  @Override
  @Transactional(readOnly = true)
  public PagedResponse<UserStatusHistoryResponse> getUserStatusHistory(Long userId, Integer page, Integer size,
                                                                        String sortBy, String sortDir,
                                                                        Long adminId) {

    // Verify user exists
    if (!userRepository.existsById(userId)) {
      throw new ResourceNotFoundException("User", "id", userId);
    }

    Pageable pageable = PaginationUtil.buildPageable(page, size, sortBy, sortDir, ALLOWED_HISTORY_SORT_FIELDS);

    Page<UserStatusHistory> historyPage = statusHistoryRepository.findByUserIdWithFilters(userId, adminId, pageable);

    // Map to response DTO with admin names resolved
    return PagedResponse.of(historyPage, history -> {
      String changedByName = null;
      if (history.getChangedByType() == ActorType.USER) {
        changedByName = "SELF";
      } else if (history.getChangedById() != null) {
        changedByName = adminRepository.findById(history.getChangedById())
          .map(admin -> admin.getFirstName() + " " +
            (admin.getLastName() != null ? admin.getLastName() : ""))
          .orElse("Unknown");
      }

      User user = history.getUser();

      return UserStatusHistoryResponse.builder()
        .id(history.getId())
        .userId(user.getUserId())
        .username(user.getUsername())
        .userFullName(user.getFullName())
        .oldStatus(history.getOldStatus())
        .newStatus(history.getNewStatus())
        .reason(history.getReason())
        .changedById(history.getChangedById())
        .changedByName(changedByName)
        .changedByType(history.getChangedByType())
        .ipAddress(history.getIpAddress())
        .changedAt(history.getChangedAt())
        .build();
    });
  }

  @Override
  @Transactional(readOnly = true)
  public ActiveSessionResponse getActiveSession(Long adminId) {

    RefreshToken token = refreshTokenRepository
      .findActiveToken(adminId, "admin", Instant.now())
      .orElseThrow(() -> new ResourceNotFoundException("ActiveSession", "adminId", adminId));

    return ActiveSessionResponse.builder()
      .tokenId(token.getRefreshTokenId())
      .ipAddress(token.getIpAddress())
      .deviceInfo(token.getDeviceInfo())
      .issuedAt(token.getCreatedAt())
      .expiresAt(token.getExpiresAt())
      .expired(token.getExpiresAt().isBefore(Instant.now()))
      .build();
  }


  public UsersAnalyticsDataResponse getUserAnalyticsData() {

    Instant now = Instant.now();
    Instant startOfToday  = now.truncatedTo(ChronoUnit.DAYS);
    Instant startOfWeek   = now.minus(7,  ChronoUnit.DAYS);
    Instant startOfMonth  = now.minus(30, ChronoUnit.DAYS);

    long totalUsers    = userRepository.count();
    long activeUsers   = userRepository.countByStatus(UserStatus.ACTIVE);

    long regToday  = userRepository.countByRegisteredAtAfter(startOfToday);
    long regWeek   = userRepository.countByRegisteredAtAfter(startOfWeek);
    long regMonth  = userRepository.countByRegisteredAtAfter(startOfMonth);

    long loginToday = userRepository.countByLastLoginAtAfter(startOfToday);
    long loginWeek  = userRepository.countByLastLoginAtAfter(startOfWeek);
    long loginMonth = userRepository.countByLastLoginAtAfter(startOfMonth);

    long emailVerified  = userRepository.countByEmailVerifiedTrue();
    long phoneVerified  = userRepository.countByPhoneVerifiedTrue();
    long fullyVerified  = userRepository.countByEmailVerifiedTrueAndPhoneVerifiedTrue();
    double emailRate    = totalUsers > 0 ? (emailVerified * 100.0 / totalUsers) : 0;
    double phoneRate    = totalUsers > 0 ? (phoneVerified * 100.0 / totalUsers) : 0;

    Double avgPwdChange = userRepository.avgPasswordChangeCount();
    long neverChanged   = userRepository.countByPasswordChangeCount(0);

    return UsersAnalyticsDataResponse.builder()
      .totalUsers(totalUsers)
      .activeUsers(activeUsers)
      .registrationsToday(regToday)
      .registrationsThisWeek(regWeek)
      .registrationsThisMonth(regMonth)
      .loginsToday(loginToday)
      .loginsThisWeek(loginWeek)
      .loginsThisMonth(loginMonth)
      .emailVerifiedUsers(emailVerified)
      .phoneVerifiedUsers(phoneVerified)
      .fullyVerifiedUsers(fullyVerified)
      .emailVerificationRate(Math.round(emailRate * 100.0) / 100.0)
      .phoneVerificationRate(Math.round(phoneRate * 100.0) / 100.0)
      .registeredByDeviceType(toMap(userRepository.countByRegisteredDeviceType()))
      .registeredByOs(toMap(userRepository.countByRegisteredOs()))
      .registeredByBrowser(toMap(userRepository.countByRegisteredBrowser()))
      .lastLoginByDeviceType(toMap(userRepository.countByLastDeviceType()))
      .lastLoginByOs(toMap(userRepository.countByLastOs()))
      .avgPasswordChangeCount(avgPwdChange != null ? Math.round(avgPwdChange * 100.0) / 100.0 : 0)
      .usersNeverChangedPassword(neverChanged)
      .build();
  }

  /** Converts List<Object[]> {key, count} rows into a LinkedHashMap */
  private Map<String, Long> toMap(List<Object[]> rows) {
    Map<String, Long> map = new LinkedHashMap<>();
    for (Object[] row : rows) {
      String key = row[0] != null ? row[0].toString() : "UNKNOWN";
      Long   val = ((Number) row[1]).longValue();
      map.put(key, val);
    }
    return map;
  }

}
