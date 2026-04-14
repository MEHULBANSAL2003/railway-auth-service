package com.railway.auth_service.dto.internal;

import lombok.Builder;
import lombok.Getter;

/**
 * IP geolocation data.
 * Internal DTO — never exposed to frontend.
 *
 * All fields nullable — geolocation can fail
 * (localhost IP, API down, rate limited).
 */
@Getter
@Builder
public class LocationInfo {

  private String city;
  private String state;
  private String country;
  private Double latitude;
  private Double longitude;
}
