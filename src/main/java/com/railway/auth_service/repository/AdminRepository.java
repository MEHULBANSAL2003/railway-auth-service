package com.railway.auth_service.repository;

import com.railway.auth_service.model.entity.Admin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AdminRepository extends JpaRepository<Admin, Long> {

  Optional<Admin> findByEmail(String email);

  Optional<Admin> findByGoogleId(String googleId);

  Optional<Admin> findByPhone(String phone);

  boolean existsByEmail(String email);

  boolean existsByPhone(String phone);
}
