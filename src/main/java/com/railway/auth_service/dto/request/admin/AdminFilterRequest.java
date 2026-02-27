package com.railway.auth_service.dto.request.admin;

import com.railway.common.enums.Department;
import com.railway.common.enums.Role;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AdminFilterRequest {

  // ── Filters ──────────────────────────────────────────────
  private String name;           // fullName ILIKE %name%
  private String email;          // email ILIKE %email%
  private String phone;          // phoneNumber ILIKE %phone%
  private Department department; // exact match
  private Role role;             // exact match
  private Boolean isActive;      // exact match (null = no filter)

  // ── Sorting ──────────────────────────────────────────────
  private String sortBy = "createdAt";   // field to sort on
  private String sortDir = "desc";       // "asc" | "desc"

  // ── Pagination ───────────────────────────────────────────
  @Min(value = 0, message = "Page must be >= 0")
  private int page = 0;

  @Min(value = 1, message = "Page size must be >= 1")
  @Max(value = 100, message = "Page size must be <= 100")
  private int size = 20;
}
