"""Pagination configuration for the multilingual task API.

Provides ``StandardResultsSetPagination`` with configurable page size
via query parameter and a maximum cap to prevent abuse.
"""

from rest_framework.pagination import PageNumberPagination


class StandardResultsSetPagination(PageNumberPagination):
    """Standard paginator with client-controlled page size.

    Attributes:
        page_size: Default items per page (20).
        page_size_query_param: Query param to override page size.
        max_page_size: Hard ceiling to prevent excessive queries.
    """

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100