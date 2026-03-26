package com.railway.auth_service.dto.request;

import com.railway.auth_service.model.enums.AdminRole;
import com.railway.auth_service.model.enums.Department;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateAdminRequest {

  @NotBlank(message = "Email is required")
  @Email(message = "Invalid email format")
  private String email;

  @NotBlank(message = "First name is required")
  @Size(min = 2, max = 100, message = "First name must be 2-100 characters")
  private String firstName;

  @Size(max = 100, message = "Last name must be under 100 characters")
  private String lastName;


  @NotBlank(message = "Phone number is required")
  @Pattern(regexp = "^\\d{10}$", message = "Phone must be exactly 10 digits")
  private String phone;

  @NotNull(message = "Department is required")
  private Department department;

  @NotNull(message = "Role is required")
  private AdminRole role;
}
