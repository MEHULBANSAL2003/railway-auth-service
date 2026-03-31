package com.railway.auth_service.service.device;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.railway.auth_service.dto.internal.DeviceInfo;
import com.railway.auth_service.dto.internal.LocationInfo;
import com.railway.auth_service.model.entity.User;
import com.railway.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import ua_parser.Client;
import ua_parser.Parser;

/**
 * Handles device/browser parsing and IP geolocation.
 *
 * Called asynchronously after login — user doesn't wait for this.
 * If anything fails, it's logged and skipped. Login is never affected.
 *
 * Two responsibilities:
 *   1. Parse User-Agent → device type, OS, browser
 *   2. Resolve IP → city, state, country
 *
 * Why one service for both?
 * Both are called together at the same time (after login).
 * Both update the same User entity.
 * Both are "login metadata" — same concern.
 * If they grow complex, split later. YAGNI.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceInfoService {

  private final UserRepository userRepository;
  private final ObjectMapper objectMapper;

  /**
   * ua_parser instance. Thread-safe, reusable.
   * Parses User-Agent strings into structured data.
   *
   * Created once — parsing the regex file is expensive (~50ms).
   * Reused for every call — actual parsing is ~1ms.
   */
  private final Parser uaParser = new Parser();

  /**
   * RestClient for IP geolocation API calls.
   * ip-api.com — free, no API key needed, 45 req/min limit.
   */
  private final RestClient geoClient = RestClient.builder()
    .baseUrl("http://ip-api.com")
    .build();

  /**
   * Updates user's login metadata asynchronously.
   *
   * @param userId    the user's DB ID
   * @param ip        client IP address
   * @param userAgent raw User-Agent header string
   *
   * Why @Async("authAsyncExecutor")?
   * Runs in a background thread from our custom pool.
   * The login method returns immediately — user gets tokens fast.
   * This method takes 100-300ms (geolocation API) but user doesn't wait.
   *
   * Why @Async on THIS method and not on parseDevice/resolveLocation?
   * One async call that does everything is simpler than multiple.
   * One thread, one DB read, one DB write. Clean.
   *
   * Why the entire method is wrapped in try-catch?
   * Async exceptions don't propagate to the caller.
   * If this fails silently, the user's device/location fields stay null.
   * That's acceptable — login metadata is nice-to-have, not critical.
   * But we MUST log the error for debugging.
   */
  @Async("authAsyncExecutor")
  public void updateLoginMetadata(Long userId, String ip, String userAgent) {
    try {
      // Parse device info from User-Agent
      DeviceInfo deviceInfo = parseDevice(userAgent);

      // Resolve location from IP
      LocationInfo locationInfo = resolveLocation(ip);

      // Fetch user and update fields
      userRepository.findById(userId).ifPresent(user -> {
        // Device info
        user.setLastDeviceType(deviceInfo.getDeviceType());
        user.setLastOs(deviceInfo.getOs());
        user.setLastBrowser(deviceInfo.getBrowser());

        // Location info
        if (locationInfo != null) {
          user.setLastLoginCity(locationInfo.getCity());
          user.setLastLoginState(locationInfo.getState());
          user.setLastLoginCountry(locationInfo.getCountry());
        }

        userRepository.save(user);
        log.debug("Login metadata updated for userId={}: device={}, os={}, browser={}, city={}",
          userId, deviceInfo.getDeviceType(), deviceInfo.getOs(),
          deviceInfo.getBrowser(),
          locationInfo != null ? locationInfo.getCity() : "unknown");
      });

    } catch (Exception e) {
      // Never let metadata failure affect anything
      log.error("Failed to update login metadata for userId={}: {}", userId, e.getMessage());
    }
  }

  /**
   * Parses User-Agent string into structured device info.
   *
   * Example input:
   *   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)..."
   *
   * Example output:
   *   DeviceInfo(deviceType="MOBILE", os="iOS 17", browser="Safari 17")
   *
   * How ua_parser works:
   *   It has a YAML file with ~1000 regex patterns for every known
   *   browser, OS, and device. It matches the User-Agent against
   *   these patterns and extracts structured data. Maintained by
   *   a community — new browsers/devices are added regularly.
   */
  private DeviceInfo parseDevice(String userAgent) {
    if (userAgent == null || userAgent.isBlank()) {
      return DeviceInfo.builder()
        .deviceType("UNKNOWN")
        .os("UNKNOWN")
        .browser("UNKNOWN")
        .build();
    }

    Client client = uaParser.parse(userAgent);

    // Device type detection
    // ua_parser gives device family: "iPhone", "iPad", "Samsung Galaxy", "Other"
    // We categorize into MOBILE, TABLET, DESKTOP
    String deviceType = detectDeviceType(client.device.family, userAgent);

    // OS: "iOS 17", "Android 14", "Windows 11", "Mac OS X 14"
    String os = buildOsString(client.os.family, client.os.major);

    // Browser: "Chrome 120", "Safari 17", "Firefox 121"
    String browser = buildBrowserString(client.userAgent.family, client.userAgent.major);

    return DeviceInfo.builder()
      .deviceType(deviceType)
      .os(os)
      .browser(browser)
      .build();
  }

  /**
   * Detects device type from device family and User-Agent string.
   *
   * Why not just use client.device.family?
   * ua_parser gives "iPhone", "iPad", "Samsung SM-G998B" etc.
   * We need categories: MOBILE, TABLET, DESKTOP.
   * ua_parser doesn't categorize — we do it ourselves.
   *
   * Why also check the raw User-Agent?
   * Some User-Agents don't have a recognized device family
   * but contain keywords like "Mobile" or "Tablet".
   */
  private String detectDeviceType(String deviceFamily, String userAgent) {
    String lower = userAgent.toLowerCase();
    String familyLower = deviceFamily != null ? deviceFamily.toLowerCase() : "";

    // Tablet detection first (iPad, tablet keyword)
    if (familyLower.contains("ipad") || lower.contains("tablet") || lower.contains("kindle")) {
      return "TABLET";
    }

    // Mobile detection
    if (familyLower.contains("iphone") || lower.contains("mobile") || lower.contains("android")) {
      // Android can be both mobile and tablet
      // "Mobile" in UA distinguishes Android phone from Android tablet
      if (lower.contains("android") && !lower.contains("mobile")) {
        return "TABLET";
      }
      return "MOBILE";
    }

    return "DESKTOP";
  }

  /**
   * Builds OS string like "iOS 17", "Windows 11".
   * Returns just family name if version is missing.
   */
  private String buildOsString(String family, String major) {
    if (family == null || "Other".equals(family)) return "UNKNOWN";
    if (major == null || major.isBlank()) return family;
    return family + " " + major;
  }

  /**
   * Builds browser string like "Chrome 120", "Safari 17".
   * Returns just family name if version is missing.
   */
  private String buildBrowserString(String family, String major) {
    if (family == null || "Other".equals(family)) return "UNKNOWN";
    if (major == null || major.isBlank()) return family;
    return family + " " + major;
  }

  /**
   * Resolves IP address to geographic location.
   *
   * Uses ip-api.com — free tier:
   *   - 45 requests per minute
   *   - No API key needed
   *   - Returns JSON with city, region, country
   *
   * Returns null for:
   *   - Localhost IPs (127.0.0.1, ::1) — no location
   *   - API failure — don't crash, just skip
   *   - Rate limited — returns null, logged as warning
   *
   * Why not cache results?
   * Same IP usually maps to same location. Caching in Redis
   * would reduce API calls. But for now, 45 req/min is enough
   * for dev. Add caching when you hit the limit. YAGNI.
   */
  private LocationInfo resolveLocation(String ip) {
    // Skip localhost — no geolocation possible
    if (ip == null || ip.equals("127.0.0.1") || ip.equals("::1") ||
      ip.equals("0:0:0:0:0:0:0:1") || ip.startsWith("192.168.") ||
      ip.startsWith("10.") || ip.startsWith("172.")) {
      log.debug("Skipping geolocation for local/private IP: {}", ip);
      return null;
    }

    try {
      String response = geoClient
        .get()
        .uri("/json/{ip}", ip)
        .retrieve()
        .body(String.class);

      JsonNode json = objectMapper.readTree(response);

      // ip-api.com returns "status": "success" or "fail"
      if (!"success".equals(json.path("status").asText())) {
        log.warn("Geolocation failed for IP {}: {}", ip, json.path("message").asText());
        return null;
      }

      return LocationInfo.builder()
        .city(json.path("city").asText(null))
        .state(json.path("regionName").asText(null))
        .country(json.path("country").asText(null))
        .build();

    } catch (Exception e) {
      log.warn("Geolocation API call failed for IP {}: {}", ip, e.getMessage());
      return null;
    }
  }
}
