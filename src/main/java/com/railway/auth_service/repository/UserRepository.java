package com.railway.auth_service.repository;

import com.railway.auth_service.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Data access layer for User entity.
 *
 * Spring Data JPA generates the implementation at runtime
 * based on method names. No SQL, no boilerplate.
 *
 * Method naming convention:
 *   findBy{Field}  → SELECT WHERE field = ?  → returns Optional<User>
 *   existsBy{Field} → SELECT count(*) > 0    → returns boolean
 *
 * Each method maps to an indexed column in the users table,
 * so all queries are fast (no full table scans).
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

  // ── Uniqueness checks (registration) ──

  /**
   * Used during registration to check if username is taken.
   * Maps to: SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)
   * Uses index: idx_users_username
   */
  boolean existsByUsername(String username);

  /**
   * Used during registration to check if email is taken.
   * Uses index: uk_users_email (unique constraint index)
   */
  boolean existsByEmail(String email);

  /**
   * Used during registration to check if phone is taken.
   * Uses index: uk_users_phone (unique constraint index)
   */
  boolean existsByPhone(String phone);

  // ── Login lookups ──

  /**
   * Find user by email for login.
   * Login flow: identifier contains "@" → search by email.
   */
  Optional<User> findByEmail(String email);

  /**
   * Find user by phone for login.
   * Login flow: identifier is 10 digits → search by phone.
   */
  Optional<User> findByPhone(String phone);

  /**
   * Find user by username for login.
   * Login flow: identifier is not email or phone → search by username.
   */
  Optional<User> findByUsername(String username);
}
