package com.railway.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Registration metadata - captured once at signup, never changes.
 * Includes device, location, and timestamp information from initial registration.
 */
@Getter
@Builder
@AllArgsConstructor
public class RegistrationMetadata {

  // ── Timestamp ──
  private Instant registeredAt;

  // ── Network ──
  private String registeredIp;

  // ── Device Info ──
  private String deviceType;    // MOBILE, DESKTOP, TABLET
  private String deviceName;    // "iPhone 14 Pro", "Realme RMX3834"
  private String os;            // "iOS 17", "Android 14"
  private String browser;       // "Safari 17", "Chrome 120"

  // ── Location Info ──
  private String city;
  private String state;
  private String country;
  private Double latitude;
  private Double longitude;
}
