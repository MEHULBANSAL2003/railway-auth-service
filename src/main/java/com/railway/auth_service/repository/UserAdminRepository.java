package com.railway.auth_service.repository;


import com.railway.auth_service.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserAdminRepository extends JpaRepository<UserEntity,Long> {
  Optional<UserEntity> findByEmail(String email);
  Optional<UserEntity> findByGoogleId(String googleId);
  Boolean existsByEmail(String email);
}
