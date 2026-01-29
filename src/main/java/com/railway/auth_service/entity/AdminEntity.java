package com.railway.auth_service.entity;


import com.railway.auth_service.enums.AdminRole;
import com.railway.auth_service.enums.Department;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "admins", indexes = {
  @Index(name = "idx_admin_email", columnList = "email"),
  @Index(name = "idx_admin_google_id", columnList = "google_id"),
})
public class AdminEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true, length = 255)
  @Email(message = "Invalid email")
  @NotBlank(message = "Email is required")
  private String email;

  @Column(name = "full_name", nullable = false, length = 255)
  @NotBlank(message = "Full name is required")
  private String fullName;

  @Column(name = "profile_picture_url", length = 500)
  private String profilePictureUrl;

  @Column(name = "google_id", unique = true, nullable = false, length = 255)
  @NotBlank(message = "Google ID is required")
  private String googleId;

  @Enumerated(EnumType.STRING)
  @Column(name = "admin_role", nullable = false, length = 50)
  @Builder.Default
  private AdminRole adminRole = AdminRole.ADMIN;

  @Column(name = "department", length = 100)
  @Builder.Default
  private Department department = Department.TECH;

  @Column(name = "is_active", nullable = false)
  @Builder.Default
  private Boolean isActive = true;

  @Column(name = "last_login_at")
  private LocalDateTime lastLoginAt;

  @Column(name = "created_by")
  private Long createdBy;

  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Column(name = "deleted_at")
  private LocalDateTime deletedAt;

  @PrePersist
  protected void onCreate() {
    createdAt = LocalDateTime.now();
    updatedAt = LocalDateTime.now();
  }

  @PreUpdate
  protected void onUpdate() {
    updatedAt = LocalDateTime.now();
  }

  public boolean canLogin() {
    return isActive;
  }

  public void updateLastLogin() {
    this.lastLoginAt = LocalDateTime.now();
  }

  public boolean isSuperAdmin() {
    return AdminRole.SUPER_ADMIN.equals(this.adminRole);
  }


}
