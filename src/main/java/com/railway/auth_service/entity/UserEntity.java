package com.railway.auth_service.entity;
import com.railway.auth_service.enums.AuthProvider;
import com.railway.auth_service.enums.Role;
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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "users",indexes = {
  @Index(name = "idx_email", columnList = "email"),
  @Index(name = "idx_phone", columnList = "phoneNumber"),
  @Index(name = "idx_google_id", columnList = "googleId")
})
public class UserEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

  @Column(nullable = false)
  @NotBlank
  private String name;

  @Column(nullable = false, unique = true, length = 50)
  private String userName;

  @Column(unique = true)
  @Pattern(regexp = "^[0-9]{10}$")
  private String phoneNumber;

  private String countryCode;

  @Column(unique = true)
  private String email;


  private String hashedPassword;

  private String oauthProviderId;

  @Column(unique = true)
  private String googleId;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private AuthProvider authProvider;

  @Column(nullable = false)
  private Boolean isActive = true;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private Role role;

  @Column(nullable = false)
  private LocalDateTime lastLoginAt;

  @Column(nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @Column(nullable = false)
  private LocalDateTime updatedAt;

  @PrePersist
  protected void onCreate() {
    createdAt = LocalDateTime.now();
    updatedAt = LocalDateTime.now();
    lastLoginAt = LocalDateTime.now();
  }

  @PreUpdate
  protected void onUpdate() {
    updatedAt = LocalDateTime.now();
  }

}
