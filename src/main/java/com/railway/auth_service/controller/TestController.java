package com.railway.auth_service.controller;

import com.railway.common.dto.ApiResponse;
import com.railway.common.exception.BadRequestException;
import com.railway.common.exception.ResourceNotFoundException;
import com.railway.common.security.AuthPrincipal;
import com.railway.common.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * TEMPORARY controller for testing common-lib integration.
 * Delete this after testing — it's not part of the real API.
 */
@Slf4j
@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
public class TestController {

  private final JwtUtil jwtUtil;

  // ─── TEST 1: ApiResponse + CorrelationId ───
  // curl http://localhost:8081/api/test/public
  //
  // Expected: { "status": "success", "data": { "message": "..." } }
  // Check terminal logs → should show [correlation-id]
  @GetMapping("/public")
  public ResponseEntity<ApiResponse<Map<String, String>>> testPublic() {
    log.info("Public endpoint hit — check correlation ID in this log");
    return ResponseEntity.ok(
      ApiResponse.success(Map.of("message", "Common-lib is working!"))
    );
  }

  // ─── TEST 2: Exception handling ───
  // curl http://localhost:8081/api/test/error-404
  //
  // Expected: HTTP 404 → { "status": "error", "reason": "Train not found with id: 999" }
  @GetMapping("/error-404")
  public ResponseEntity<Void> testNotFound() {
    throw new ResourceNotFoundException("Train", "id", 999);
  }

  // ─── TEST 3: Exception handling (400) ───
  // curl http://localhost:8081/api/test/error-400
  //
  // Expected: HTTP 400 → { "status": "error", "reason": "Departure date cannot be in the past" }
  @GetMapping("/error-400")
  public ResponseEntity<Void> testBadRequest() {
    throw new BadRequestException("Departure date cannot be in the past");
  }

  // ─── TEST 4: Unexpected error (safety net) ───
  // curl http://localhost:8081/api/test/error-500
  //
  // Expected: HTTP 500 → { "status": "error", "reason": "Something went wrong. Please try again later." }
  // Check terminal → should show full stack trace in logs
  @GetMapping("/error-500")
  public ResponseEntity<Void> testUnexpectedError() {
    throw new RuntimeException("Simulated unexpected error");
  }

  // ─── TEST 5: Generate a dummy token ───
  // curl http://localhost:8081/api/test/token
  //
  // Expected: { "status": "success", "data": { "accessToken": "eyJ...", "type": "admin" } }
  @GetMapping("/token")
  public ResponseEntity<ApiResponse<Map<String, String>>> testGenerateToken() {
    String token = jwtUtil.generateAccessToken(1L, "priya@company.com", "SUPER_ADMIN", "admin");
    log.info("Generated test token for admin id=1");
    return ResponseEntity.ok(
      ApiResponse.success(Map.of(
        "accessToken", token,
        "type", "admin"
      ))
    );
  }

  // ─── TEST 6: Protected endpoint (needs token) ───
  // Step 1: Get token from /api/test/token
  // Step 2: curl -H "Authorization: Bearer <token>" http://localhost:8081/api/test/protected
  //
  // Expected: { "status": "success", "data": { "id": "1", "type": "admin", ... } }
  // Without token: HTTP 403
  @GetMapping("/protected")
  public ResponseEntity<ApiResponse<Map<String, String>>> testProtected(
    @AuthenticationPrincipal AuthPrincipal principal) {
    log.info("Protected endpoint accessed by {} id={}", principal.getType(), principal.getId());
    return ResponseEntity.ok(
      ApiResponse.success(Map.of(
        "id", String.valueOf(principal.getId()),
        "email", principal.getEmail(),
        "role", principal.getRole(),
        "type", principal.getType()
      ))
    );
  }
}
