package com.railway.auth_service.repository;

import com.railway.auth_service.entity.AdminEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AdminRepository extends JpaRepository<AdminEntity, Long> {
  Optional<AdminEntity> findByEmail(String email);
}
