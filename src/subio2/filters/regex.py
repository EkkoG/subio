"""Regular expression based filter."""

import re
from typing import List
from ..core.interfaces import Filter
from ..core.registry import filter_registry
from ..models import Node


@filter_registry.decorator("regex")
class RegexFilter(Filter):
    """Filter nodes using regular expressions."""

    def __init__(self, include: str = None, exclude: str = None):
        """Initialize with include/exclude patterns."""
        self.include_pattern = re.compile(include) if include else None
        self.exclude_pattern = re.compile(exclude) if exclude else None

    @property
    def name(self) -> str:
        """Return filter name."""
        return "regex"

    def filter(self, nodes: List[Node]) -> List[Node]:
        """Filter nodes based on regex patterns."""
        filtered = nodes

        # Apply exclude filter first
        if self.exclude_pattern:
            filtered = [n for n in filtered if not self.exclude_pattern.match(n.name)]

        # Then apply include filter
        if self.include_pattern:
            filtered = [n for n in filtered if self.include_pattern.match(n.name)]

        return filtered
