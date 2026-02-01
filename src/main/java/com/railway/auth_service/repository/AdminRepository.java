package com.railway.auth_service.repository;

import com.railway.auth_service.entity.AdminEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AdminRepository extends JpaRepository<AdminEntity, Long> {
  Optional<AdminEntity> findByEmail(String email);
  Boolean existsByEmail(String email);
  Boolean existsByPhoneNumber(String phoneNumber);

  @Query("""
       SELECT COUNT(a) > 0
       FROM AdminEntity a
       WHERE a.email = :email
          OR a.phoneNumber = :phoneNumber
       """)
  boolean existsByEmailOrPhone(String email,String phoneNumber);
}
