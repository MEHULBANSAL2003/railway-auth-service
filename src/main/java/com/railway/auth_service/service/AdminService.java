package com.railway.auth_service.service;

import com.railway.auth_service.dto.request.CreateAdminRequest;
import com.railway.auth_service.dto.response.ActiveSessionResponse;
import com.railway.auth_service.dto.response.AdminResponse;
import com.railway.auth_service.dto.response.AdminUserDetailResponse;
import com.railway.auth_service.dto.response.CreateAdminResponse;
import com.railway.auth_service.dto.response.UserStatusHistoryResponse;
import com.railway.common.dto.PagedResponse;

import java.util.Map;

public interface AdminService {

  CreateAdminResponse createAdmin(CreateAdminRequest request, Long createdBy);

  Map<String, Object> toggleStatus(Long adminId, Long requestedBy);

  Map<String, Object> changeRole(Long adminId, Long requestedBy);

  PagedResponse<AdminResponse> listAdmins(Integer page, Integer size,
                                          String sortBy, String sortDir,
                                          String role, String department,
                                          Boolean enabled, String searchName,
                                          String searchEmail, String searchPhone,
                                          String search);

  AdminResponse getAdminById(Long adminId);

  AdminResponse getOwnProfile(Long adminId);

  AdminUserDetailResponse getUserById(Long userId);

  PagedResponse<UserStatusHistoryResponse> getUserStatusHistory(Long userId, Integer page, Integer size,
                                                                 String sortBy, String sortDir,
                                                                 Long adminId);

  ActiveSessionResponse getActiveSession(Long adminId);
}
