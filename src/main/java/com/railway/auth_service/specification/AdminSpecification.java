package com.railway.auth_service.specification;

import com.railway.auth_service.dto.request.admin.AdminFilterRequest;
import com.railway.auth_service.entity.AdminEntity;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

public final class AdminSpecification {

  private AdminSpecification() {}

  public static Specification<AdminEntity> withFilters(AdminFilterRequest filter) {
    return (root, query, cb) -> {

      List<Predicate> predicates = new ArrayList<>();

      // ── 1. Full name (case-insensitive LIKE) ─────────────
      if (hasText(filter.getName())) {
        predicates.add(cb.like(cb.lower(root.get("fullName")), contains(filter.getName())));
      }

      // ── 2. Email (case-insensitive LIKE) ─────────────────
      if (hasText(filter.getEmail())) {
        predicates.add(cb.like(cb.lower(root.get("email")), contains(filter.getEmail())));
      }

      // ── 3. Phone (partial match) ──────────────────────────
      if (hasText(filter.getPhone())) {
        predicates.add(cb.like(root.get("phoneNumber"), contains(filter.getPhone())));
      }

      // ── 4. Department (exact) ─────────────────────────────
      if (filter.getDepartment() != null) {
        predicates.add(cb.equal(root.get("department"), filter.getDepartment()));
      }

      // ── 5. Role (exact) ───────────────────────────────────
      if (filter.getRole() != null) {
        predicates.add(cb.equal(root.get("adminRole"), filter.getRole()));
      }

      // ── 6. isActive — null means no filter (show all) ────
      if (filter.getIsActive() != null) {
        predicates.add(cb.equal(root.get("isActive"), filter.getIsActive()));
      }

      query.distinct(true);

      return cb.and(predicates.toArray(new Predicate[0]));
    };
  }

  private static String contains(String value) {
    return "%" + value.trim().toLowerCase() + "%";
  }

  private static boolean hasText(String value) {
    return value != null && !value.isBlank();
  }
}
