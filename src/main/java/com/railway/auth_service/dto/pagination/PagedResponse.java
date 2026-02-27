package com.railway.auth_service.dto.pagination;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.domain.Page;

import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Generic paginated response wrapper.
 * Use across every paginated list endpoint in the system.
 *
 * <pre>
 * PagedResponse<AdminSummaryResponse> paged =
 *     PagedResponse.from(adminPage, AdminMapper::toSummary);
 * </pre>
 */
@Getter
@Builder
public class PagedResponse<T> {

  private List<T> content;

  // ── Page meta ────────────────────────────────────────────
  private int  page;          // current page (0-indexed)
  private int  size;          // requested page size
  private long totalElements; // total matching records
  private int  totalPages;    // total pages
  private boolean first;      // is this the first page?
  private boolean last;       // is this the last page?
  private boolean hasNext;
  private boolean hasPrevious;

  // ── Sort meta ────────────────────────────────────────────
  private String sortBy;
  private String sortDir;

  /**
   * Build a PagedResponse from a Spring Data {@link Page} and a mapper function.
   *
   * @param page   the Spring Page result
   * @param mapper function to convert entity → response DTO
   */
  public static <E, R> PagedResponse<R> from(Page<E> page, Function<E, R> mapper) {
    List<R> content = page.getContent()
      .stream()
      .map(mapper)
      .collect(Collectors.toList());

    return PagedResponse.<R>builder()
      .content(content)
      .page(page.getNumber())
      .size(page.getSize())
      .totalElements(page.getTotalElements())
      .totalPages(page.getTotalPages())
      .first(page.isFirst())
      .last(page.isLast())
      .hasNext(page.hasNext())
      .hasPrevious(page.hasPrevious())
      .build();
  }

  /**
   * Same as above but also attaches sort metadata from the request.
   */
  public static <E, R> PagedResponse<R> from(Page<E> page, Function<E, R> mapper,
                                             String sortBy, String sortDir) {
    PagedResponse<R> response = from(page, mapper);
    return PagedResponse.<R>builder()
      .content(response.content)
      .page(response.page)
      .size(response.size)
      .totalElements(response.totalElements)
      .totalPages(response.totalPages)
      .first(response.first)
      .last(response.last)
      .hasNext(response.hasNext)
      .hasPrevious(response.hasPrevious)
      .sortBy(sortBy)
      .sortDir(sortDir)
      .build();
  }
}
