package com.railway.auth_service.repository;

import com.railway.auth_service.model.entity.Admin;
import com.railway.auth_service.model.enums.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface AdminRepository extends JpaRepository<Admin, Long>, JpaSpecificationExecutor<Admin> {

  Optional<Admin> findByEmail(String email);

  Optional<Admin> findByGoogleId(String googleId);

  Optional<Admin> findByPhone(String phone);

  boolean existsByEmail(String email);

  boolean existsByPhone(String phone);


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

}
