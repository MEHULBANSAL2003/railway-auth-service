package com.railway.auth_service.repository;

import com.railway.auth_service.model.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

  Optional<RefreshToken> findByRefreshToken(String refreshToken);

  @Modifying
  @Query("UPDATE RefreshToken rt SET rt.revoked = true " +
    "WHERE rt.ownerId = :ownerId AND rt.ownerType = :ownerType " +
    "AND rt.revoked = false")
  void revokeAllByOwner(@Param("ownerId") Long ownerId,
                        @Param("ownerType") String ownerType);
}
