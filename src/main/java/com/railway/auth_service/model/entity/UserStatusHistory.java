package com.railway.auth_service.model.entity;

import com.railway.auth_service.model.enums.ActorType;
import com.railway.auth_service.model.enums.UserStatus;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(
  name = "user_status_history",
  schema = "railway_auth",
  indexes = {
    @Index(name = "idx_status_history_user_id", columnList = "user_id"),
    @Index(name = "idx_status_history_changed_at", columnList = "changed_at")
  }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserStatusHistory {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id", nullable = false, foreignKey = @ForeignKey(name = "fk_status_history_user"))
  private User user;

  @Enumerated(EnumType.STRING)
  @Column(name = "old_status", length = 20)
  private UserStatus oldStatus;

  @Enumerated(EnumType.STRING)
  @Column(name = "new_status", nullable = false, length = 20)
  private UserStatus newStatus;

  @Column(length = 500)
  private String reason;

  @Column(name = "changed_by_id")
  private Long changedById;

  @Enumerated(EnumType.STRING)
  @Column(name = "changed_by_type", nullable = false, length = 10)
  private ActorType changedByType;

  @Column(name = "ip_address", length = 45)
  private String ipAddress;

  @Column(name = "changed_at", nullable = false)
  private Instant changedAt;
}
