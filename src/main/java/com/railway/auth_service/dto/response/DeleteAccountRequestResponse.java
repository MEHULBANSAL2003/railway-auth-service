package com.railway.auth_service.dto.response;

import lombok.Builder;
import lombok.Getter;

/**
 * Response for account deletion request.
 *
 * Backend-driven approach:
 *   - message → display confirmation message
 *   - recoveryPeriodDays → inform user how many days they have to cancel
 *
 * Why backend-driven?
 * If grace period changes from 7 to 14 days, only backend config changes.
 * Frontend displays the actual configured value, not a hardcoded number.
 */
@Getter
@Builder
public class DeleteAccountRequestResponse {

  private String message;
  private int recoveryPeriodDays;
}
