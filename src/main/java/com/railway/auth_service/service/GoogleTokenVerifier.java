package com.railway.auth_service.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.railway.common.exception.UnauthorizedException;
import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * Verifies Google ID tokens using Google's official client library.
 *
 * HOW IT WORKS:
 *   GoogleIdTokenVerifier downloads Google's public keys on first use,
 *   caches them, and verifies the JWT signature locally. No HTTP call
 *   to Google per login — just local cryptographic verification.
 *
 *   The library handles:
 *     - Downloading Google's public keys (from googleapis.com)
 *     - Caching keys (refreshes automatically when they rotate)
 *     - Verifying JWT signature (token wasn't tampered)
 *     - Checking expiry (token isn't expired)
 *     - Checking issuer (token is from accounts.google.com)
 *     - Checking audience (token was issued for OUR app)
 *
 * WHY local verification (not REST API call)?
 *   - Faster: no network round-trip per login
 *   - Reliable: works even if Google's tokeninfo API is slow
 *   - Recommended: Google's official documentation suggests this
 *   - Secure: same cryptographic guarantees
 *
 * SINGLE RESPONSIBILITY:
 *   This class only verifies Google tokens. No business logic,
 *   no database calls, no JWT creation. AdminAuthServiceImpl
 *   calls this and decides what to do with the result.
 */
@Slf4j
@Service
public class GoogleTokenVerifier {

  @Value("${google.client.id}")
  private String googleClientId;

  private GoogleIdTokenVerifier verifier;

  /**
   * Initialize the verifier after Spring injects the client ID.
   *
   * WHY @PostConstruct?
   *   @Value fields are null in the constructor.
   *   @PostConstruct runs after injection — safe to use googleClientId.
   *
   * WHY setAudience?
   *   The audience check ensures the token was issued for YOUR app.
   *   Without it, someone could take a Google token from a different
   *   app and use it on yours. The audience must match your client ID.
   */
  @PostConstruct
  public void init() {
    this.verifier = new GoogleIdTokenVerifier.Builder(
      new NetHttpTransport(),
      GsonFactory.getDefaultInstance()
    )
      .setAudience(Collections.singletonList(googleClientId))
      .build();
  }

  /**
   * Verifies a Google ID token and extracts user info.
   *
   * @param idTokenString the raw Google ID token from the frontend
   * @return verified Google user info
   * @throws UnauthorizedException if token is invalid, expired,
   *         tampered, or issued for a different app
   */
  public GoogleUserInfo verify(String idTokenString) {
    try {
      GoogleIdToken idToken = verifier.verify(idTokenString);

      if (idToken == null) {
        log.warn("Google token verification returned null — invalid or expired token");
        throw new UnauthorizedException("Invalid Google authentication token");
      }

      GoogleIdToken.Payload payload = idToken.getPayload();

      return GoogleUserInfo.builder()
        .googleId(payload.getSubject())
        .email(payload.getEmail())
        .firstName((String) payload.get("given_name"))
        .lastName((String) payload.get("family_name"))
        .profileImageUrl((String) payload.get("picture"))
        .emailVerified(payload.getEmailVerified())
        .build();

    } catch (UnauthorizedException ex) {
      throw ex;
    } catch (Exception ex) {
      log.error("Google token verification failed: {}", ex.getMessage());
      throw new UnauthorizedException("Google authentication failed");
    }
  }

  /**
   * Verified Google user info.
   *
   * Immutable — once Google verifies, this data is a fact.
   * No setters, no modification after construction.
   */
  @Getter
  @Builder
  @AllArgsConstructor
  public static class GoogleUserInfo {
    private final String googleId;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final String profileImageUrl;
    private final boolean emailVerified;
  }
}
