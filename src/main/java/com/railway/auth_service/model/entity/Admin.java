package com.railway.auth_service.model.entity;


import com.railway.auth_service.model.enums.AdminRole;
import com.railway.auth_service.model.enums.Department;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;


@Entity
@Table(
  name = "admins",
  schema = "railway_auth",
  uniqueConstraints = {
    @UniqueConstraint(name = "uk_admins_email", columnNames = "email"),
    @UniqueConstraint(name = "uk_admins_phone", columnNames = "phone"),
    @UniqueConstraint(name = "uk_admins_google_id", columnNames = "google_id")
  }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Admin {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "admin_id")
  private Long adminId;

  @Column(nullable = false, length = 255)
  private String email;

  @Column(name = "first_name", nullable = false, length = 100)
  private String firstName;

  @Column(name = "last_name", length = 100)
  private String lastName;

  /**
   * Google's unique user identifier ("sub" claim from Google JWT).
   * Nullable because it's not known at creation time — super_admin
   * creates the admin with just email. The googleId gets filled
   * on the admin's first Google login.
   *
   * WHY unique?
   *   One Google account = one admin. Prevents someone from linking
   *   the same Google account to multiple admin records.
   */
  @Column(name = "google_id", length = 255, unique = true)
  private String googleId;

  /**
   * Profile picture URL from Google OAuth response.
   * Auto-filled on first login. Nullable — no image until first login.
   * Length 500 because Google image URLs can be long.
   */
  @Column(name = "profile_image_url", length = 500)
  private String profileImageUrl;

  /**
   * Country code stored separately from phone number.
   * Default "+91" for India. Stored with the "+" prefix
   * so it's ready to use in any format: +919876543210
   *
   * WHY separate from phone?
   *   - Validation: phone is exactly 10 digits, country code varies
   *   - Display: frontend might show "+91 98765 43210"
   *   - Future: if you support admins from other countries
   */
  @Column(name = "country_code", nullable = false, length = 5)
  @Builder.Default
  private String countryCode = "+91";

  /**
   * Phone number — exactly 10 digits, no spaces, no dashes.
   * Stored as String not Long because:
   *   - Leading zeros matter in some number formats
   *   - Phone numbers aren't "numbers" — you don't do math on them
   *   - Consistent with how every production system stores phones
   *
   * Validation (exactly 10 digits) is enforced at the DTO layer,
   * not here. Entities represent data shape, DTOs enforce business rules.
   */
  @Column(nullable = false, length = 10, unique = true)
  private String phone;

  /**
   * Department this admin belongs to.
   * Stored as string "OPERATIONS", "FINANCE" etc. in the DB.
   *
   * EnumType.STRING (not ORDINAL) — critical.
   * ORDINAL stores 0, 1, 2... If you add a new department between
   * existing ones, all numbers shift and existing data is corrupted.
   * STRING stores the actual name — safe to reorder, rename, or add.
   */
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 50)
  private Department department;

  /**
   * Admin's role — SUPER_ADMIN or ADMIN.
   * Same EnumType.STRING reasoning as department.
   */
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private AdminRole role;

  /**
   * Email verified flag.
   * false when super_admin creates the admin (email not yet proven).
   * true after first successful Google login (Google confirmed ownership).
   */
  @Column(name = "is_email_verified", nullable = false)
  @Builder.Default
  private boolean emailVerified = false;

  /**
   * Soft delete / access revocation.
   * false = admin can't login even with valid Google auth.
   * We don't hard-delete admins — audit trail needs the record.
   */
  @Column(name = "is_enabled", nullable = false)
  @Builder.Default
  private boolean enabled = true;

  /**
   * Last successful login timestamp. Nullable — null until first login.
   * Updated on every successful Google auth.
   */
  @Column(name = "last_login_at")
  private Instant lastLoginAt;

  /**
   * IP address of the last login.
   * VARCHAR(45) — fits both IPv4 ("192.168.1.1" = 15 chars)
   * and IPv6 ("2001:0db8:85a3:0000:0000:8a2e:0370:7334" = 39 chars).
   * 45 gives a small buffer.
   */
  @Column(name = "last_login_ip", length = 45)
  private String lastLoginIp;

  /**
   * Auto-set on insert, never changes.
   *
   * @CreationTimestamp — Hibernate sets this automatically when
   * the entity is first persisted. No manual setting needed.
   * updatable = false ensures it can't be accidentally overwritten.
   */
  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  /**
   * Auto-updated on every save.
   *
   * @UpdateTimestamp — Hibernate updates this automatically
   * whenever the entity is modified and saved.
   */
  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;

  /**
   * Which super_admin created this admin.
   * Null for the system-seeded super_admin (nobody created them).
   *
   * WHY not @ManyToOne with a self-join?
   *   We COULD do:
   *     @ManyToOne
   *     @JoinColumn(name = "created_by")
   *     private Admin createdByAdmin;
   *
   *   But that forces a JOIN every time you load an admin just to
   *   get the creator's info. We rarely need the full creator object —
   *   usually just the ID for logging/audit. Storing the raw ID is
   *   simpler and avoids lazy loading issues.
   *
   *   If you ever need the creator's details, one query:
   *     adminRepo.findById(admin.getCreatedBy())
   */
  @Column(name = "created_by")
  private Long createdBy;
}
