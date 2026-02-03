package com.railway.auth_service.dto.response.admin;


import com.railway.auth_service.enums.Department;
import com.railway.common.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateAdminResponse {

  Long id;
  String name;
  String email;
  Department department;
  Role adminRole;
  LocalDateTime createdAt;

}
