package com.railway.auth_service.dto.request.admin;

import com.railway.common.enums.Department;
import com.railway.common.enums.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
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
 @Pattern(regexp = "^[0-9]{10}$", message = "Phone number must be exactly 10 digits")
 private String phoneNumber;

  private Role role = Role.ADMIN;

  @NotNull(message = "Department is required")
  private Department department;
}
