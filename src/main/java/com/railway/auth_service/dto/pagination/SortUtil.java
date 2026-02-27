package com.railway.auth_service.dto.pagination;

import com.railway.common.exceptions.BaseException;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;

import java.util.Set;

/**
 * Utility for building validated {@link Sort} objects from user input.
 *
 * Always use this instead of directly trusting user-supplied sort field names —
 * passing arbitrary field names to Sort can expose internal field names or
 * cause runtime errors if the field doesn't exist.
 */
public final class SortUtil {

  private SortUtil() {}

  /**
   * Build a {@link Sort} from user-supplied sortBy and sortDir.
   *
   * @param sortBy        the field name to sort on
   * @param sortDir       "asc" or "desc" (case-insensitive)
   * @param allowedFields the set of fields this caller permits sorting on
   * @return a validated Sort object
   * @throws BaseException 400 if sortBy is not in allowedFields or sortDir is invalid
   */
  public static Sort build(String sortBy, String sortDir, Set<String> allowedFields) {
    // Validate field
    if (!allowedFields.contains(sortBy)) {
      throw new BaseException(
        HttpStatus.BAD_REQUEST,
        "INVALID_SORT_FIELD",
        "Cannot sort by '" + sortBy + "'. Allowed fields: " + allowedFields
      );
    }

    // Validate direction
    Sort.Direction direction = parseDirection(sortDir);

    return Sort.by(direction, sortBy);
  }

  /**
   * Parse direction string, defaulting to DESC on invalid input.
   */
  public static Sort.Direction parseDirection(String sortDir) {
    if (sortDir == null) return Sort.Direction.DESC;
    return sortDir.equalsIgnoreCase("asc")
      ? Sort.Direction.ASC
      : Sort.Direction.DESC;
  }
}
