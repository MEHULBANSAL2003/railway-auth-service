package com.railway.auth_service.repository;

import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.enums.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
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


  long countByStatus(UserStatus status);

  long countByRegisteredAtAfter(Instant after);

  // ── Logins ──
  long countByLastLoginAtAfter(Instant after);

  long countByEmailVerifiedTrue();
  long countByPhoneVerifiedTrue();
  long countByEmailVerifiedTrueAndPhoneVerifiedTrue();


  @Query("SELECT u.registeredDeviceType AS key, COUNT(u) AS value " +
    "FROM User u WHERE u.registeredDeviceType IS NOT NULL " +
    "GROUP BY u.registeredDeviceType")
  List<Object[]> countByRegisteredDeviceType();

  @Query("SELECT u.registeredOs AS key, COUNT(u) AS value " +
    "FROM User u WHERE u.registeredOs IS NOT NULL " +
    "GROUP BY u.registeredOs")
  List<Object[]> countByRegisteredOs();

  @Query("SELECT u.registeredBrowser AS key, COUNT(u) AS value " +
    "FROM User u WHERE u.registeredBrowser IS NOT NULL " +
    "GROUP BY u.registeredBrowser")
  List<Object[]> countByRegisteredBrowser();

  // ── Last login device ──
  @Query("SELECT u.lastDeviceType AS key, COUNT(u) AS value " +
    "FROM User u WHERE u.lastDeviceType IS NOT NULL " +
    "GROUP BY u.lastDeviceType")
  List<Object[]> countByLastDeviceType();

  @Query("SELECT u.lastOs AS key, COUNT(u) AS value " +
    "FROM User u WHERE u.lastOs IS NOT NULL " +
    "GROUP BY u.lastOs")
  List<Object[]> countByLastOs();


  @Query("SELECT AVG(u.passwordChangeCount) FROM User u")
  Double avgPasswordChangeCount();

  long countByPasswordChangeCount(int count);

  // ── Account Deletion Analytics ──

  /**
   * Count accounts deleted after a specific date.
   * Used for: accountsDeletedToday, accountsDeletedLast7Days, accountsDeletedLast30Days
   */
  long countByDeletedAtAfter(Instant after);

  /**
   * Count accounts with deletion scheduled after a specific date.
   * Used for: deletionRequestsToday, deletionRequestsLast7Days, deletionRequestsLast30Days
   */
  long countByDeletionScheduledAtAfter(Instant after);


  List<User> findAllByEmailVerifiedFalse();

  List<User> findAllByStatus(UserStatus status);
}
