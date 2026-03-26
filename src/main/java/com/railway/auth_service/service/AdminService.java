package com.railway.auth_service.service;

import com.railway.auth_service.dto.request.CreateAdminRequest;
import com.railway.auth_service.dto.response.CreateAdminResponse;

public interface AdminService {

  CreateAdminResponse createAdmin(CreateAdminRequest request, Long createdBy);
}
