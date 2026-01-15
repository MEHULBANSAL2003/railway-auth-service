package com.railway.auth_service.entity;
import com.railway.auth_service.enums.Role;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "users")
@Getter
@Setter
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

  @Column(nullable = false)
  private String hashedPassword;

  private Boolean isActive;
  private Boolean isVerified;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private Role role;

  private Instant lastLoginAt;
  private Instant createdAt;
  private Instant updatedAt;

}
