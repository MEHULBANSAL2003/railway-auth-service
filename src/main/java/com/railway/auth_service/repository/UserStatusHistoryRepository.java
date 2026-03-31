package com.railway.auth_service.repository;

import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.model.entity.UserStatusHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserStatusHistoryRepository extends JpaRepository<UserStatusHistory, Long> {

  List<UserStatusHistory> findByUserOrderByChangedAtDesc(User user);
}
