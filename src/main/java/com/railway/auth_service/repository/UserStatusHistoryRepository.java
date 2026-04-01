package com.railway.auth_service.repository;

import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.entity.UserStatusHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserStatusHistoryRepository extends JpaRepository<UserStatusHistory, Long> {

  List<UserStatusHistory> findByUserOrderByChangedAtDesc(User user);

  /**
   * Find status history for a specific user with optional filtering by adminId
   * Uses LEFT JOIN FETCH to eagerly load user data in single query (prevents N+1)
   */
  @Query("""
    SELECT DISTINCT ush FROM UserStatusHistory ush
    LEFT JOIN FETCH ush.user u
    WHERE u.userId = :userId
    AND (:adminId IS NULL OR ush.changedById = :adminId)
    """)
  Page<UserStatusHistory> findByUserIdWithFilters(
    @Param("userId") Long userId,
    @Param("adminId") Long adminId,
    Pageable pageable
  );
}
