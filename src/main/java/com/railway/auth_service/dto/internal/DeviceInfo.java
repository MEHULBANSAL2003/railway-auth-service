package com.railway.auth_service.dto.internal;

import lombok.Builder;
import lombok.Getter;

/**
 * Parsed User-Agent data.
 * Internal DTO — never exposed to frontend.
 */
@Getter
@Builder
public class DeviceInfo {

  /**
   * DESKTOP, MOBILE, TABLET, or UNKNOWN.
   */
  private String deviceType;

  /**
   * Device model name: "iPhone 14 Pro", "Realme RMX3834", "Samsung SM-G998B", etc.
   * Can be null if device is not recognized.
   */
  private String deviceName;

  /**
   * OS name with version: "Windows 11", "macOS 14", "Android 14", "iOS 17"
   */
  private String os;

  /**
   * Browser name with version: "Chrome 120", "Safari 17", "Firefox 121"
   */
  private String browser;
}
