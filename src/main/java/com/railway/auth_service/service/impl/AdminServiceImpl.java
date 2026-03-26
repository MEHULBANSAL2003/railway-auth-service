package com.railway.auth_service.service.impl;

import com.railway.auth_service.dto.request.CreateAdminRequest;
import com.railway.auth_service.dto.response.CreateAdminResponse;
import com.railway.auth_service.mapper.AdminMapper;
import com.railway.auth_service.model.entity.Admin;
import com.railway.auth_service.model.enums.AdminRole;
import com.railway.auth_service.repository.AdminRepository;
import com.railway.auth_service.service.AdminService;
import com.railway.common.exception.ConflictException;
import com.railway.common.exception.ForbiddenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

  private final AdminRepository adminRepository;
  private final AdminMapper adminMapper;

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
}
