package com.railway.auth_service.dto.request.admin;

import com.railway.auth_service.enums.Department;
import com.railway.common.enums.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class CreateAdminRequest {

  @NotBlank(message = "Name is required")
  private String fullName;

  @NotBlank(message = "Email is required")
  @Email(message = "Invalid email format")
  private String email;

 private String countryCode;

 @NotBlank(message = "Phone number is required")
 private String phoneNumber;

 private Role role;

 private Department department;

}
