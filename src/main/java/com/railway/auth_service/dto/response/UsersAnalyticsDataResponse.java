package com.railway.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Map;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UsersAnalyticsDataResponse {

  // ── Overview ──
  private long totalUsers;
  private long activeUsers;

  // ── Registrations ──
  private long registrationsToday;
  private long registrationsThisWeek;
  private long registrationsThisMonth;

  // ── Logins ──
  private long loginsToday;
  private long loginsThisWeek;
  private long loginsThisMonth;

  // ── Verification ──
  private long emailVerifiedUsers;
  private long phoneVerifiedUsers;
  private long fullyVerifiedUsers;         // both email + phone
  private double emailVerificationRate;    // percentage
  private double phoneVerificationRate;

  // ── Device Breakdown (at registration) ──
  private Map<String, Long> registeredByDeviceType;   // MOBILE, DESKTOP, TABLET
  private Map<String, Long> registeredByOs;           // Android, iOS, Windows, etc.
  private Map<String, Long> registeredByBrowser;

  // ── Last Login Device Breakdown ──
  private Map<String, Long> lastLoginByDeviceType;
  private Map<String, Long> lastLoginByOs;


  // ── Password ──
  private double avgPasswordChangeCount;
  private long usersNeverChangedPassword;
}
