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

}
