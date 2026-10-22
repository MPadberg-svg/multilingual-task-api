"""Pagination strategies for standard offset queries and 1M+ row keyset cursor scans.

Provides:
    - ``StandardResultsSetPagination``: Default offset paginator (``?page=1&page_size=20``)
      that transparently switches to $O(1)$ keyset cursor mode when ``?pagination=cursor``
      or ``?cursor=<opaque>`` is supplied.
    - ``KeysetCursorPagination``: Dedicated DRF ``CursorPagination`` ordered by
      ``("-created_at", "-id")`` so concurrent/bulk inserts at identical timestamps
      never skip or duplicate records.
"""

from __future__ import annotations

from typing import Any

from django.db.models import QuerySet

from rest_framework.pagination import CursorPagination, PageNumberPagination
from rest_framework.request import Request
from rest_framework.response import Response


class KeysetCursorPagination(CursorPagination):
    """Deterministic composite-keyset cursor paginator for large tables (1M+ rows)."""

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100
    cursor_query_param = "cursor"
    ordering = ("-created_at", "-id")

    def get_paginated_response(self, data: Any) -> Response:
        response = super().get_paginated_response(data)
        response["X-Pagination-Mode"] = "cursor"
        return response


class StandardResultsSetPagination(PageNumberPagination):
    """Hybrid offset + keyset-cursor paginator.

    Defaults to standard page-number pagination for backward compatibility, and
    activates $O(1)$ ``KeysetCursorPagination`` whenever ``?pagination=cursor``
    or ``?cursor=...`` is present on the request.
    """

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100

    def __init__(self) -> None:
        super().__init__()
        self._cursor_delegate: KeysetCursorPagination | None = None

    @staticmethod
    def _wants_cursor_mode(request: Request) -> bool:
        if "cursor" in request.query_params:
            return True
        return str(request.query_params.get("pagination", "")).strip().lower() == "cursor"

    def paginate_queryset(
        self,
        queryset: QuerySet[Any],
        request: Request,
        view: Any = None,
    ) -> list[Any] | None:
        if self._wants_cursor_mode(request):
            self._cursor_delegate = KeysetCursorPagination()
            return self._cursor_delegate.paginate_queryset(queryset, request, view=view)
        self._cursor_delegate = None
        return super().paginate_queryset(queryset, request, view=view)

    def get_paginated_response(self, data: Any) -> Response:
        if self._cursor_delegate is not None:
            return self._cursor_delegate.get_paginated_response(data)
        response = super().get_paginated_response(data)
        response["X-Pagination-Mode"] = "offset"
        return response
