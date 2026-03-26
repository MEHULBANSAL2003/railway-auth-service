package com.railway.auth_service.service;

import com.railway.auth_service.dto.request.CreateAdminRequest;
import com.railway.auth_service.dto.response.CreateAdminResponse;

import java.util.Map;

public interface AdminService {

  CreateAdminResponse createAdmin(CreateAdminRequest request, Long createdBy);

  Map<String, Object> toggleStatus(Long adminId, Long requestedBy);

  Map<String, Object> changeRole(Long adminId, Long requestedBy);
}
