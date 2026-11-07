from abc import ABC, abstractmethod
from collections import Counter, defaultdict, deque
from collections.abc import Callable
from typing import Any

from subio_v2.adapters.catalog import normalize_format
from subio_v2.adapters.target import TargetValidationService
from subio_v2.core.nodes import Node
from subio_v2.core.results import (
    ConversionIssue,
    EmissionResult,
    IssueSeverity,
    TargetCheckResult,
)
from subio_v2.infrastructure.logging import logger


class BaseEmitter(ABC):
    """Base class for checked, structured subscription emitters."""

    platform: str = ""

    def __init__(self):
        self.platform = normalize_format(self.platform)
        self._conversion = TargetValidationService(self.platform)
        self.target_context = self._conversion.target_context

    @abstractmethod
    def emit_result(self, nodes: list[Node]) -> EmissionResult[Any]:
        """Return content, actually emitted nodes, and structured issues."""

    def check_node(self, node: Node) -> TargetCheckResult:
        return self._conversion.check_node(node)

    def issue_for_node(
        self,
        node: Node,
        severity: IssueSeverity,
        message: str,
        *,
        field: str | None = None,
        suggestion: str | None = None,
        stage: str = "emit",
        code: str = "conversion",
    ) -> ConversionIssue:
        return self._conversion.issue_for_node(
            node,
            severity,
            message,
            field=field,
            suggestion=suggestion,
            stage=stage,
            code=code,
        )

    def encode_node(
        self, node: Node, encoder: Callable[[Node], object]
    ):
        return self._conversion.encode_node(node, encoder, self.check_node)

    def retain_dialer_indices(
        self, source: list[Node], candidates: list[Node]
    ) -> tuple[set[int], list[ConversionIssue]]:
        """Remove dependencies on rejected internal nodes; external names stay local to templates."""
        retained = set(range(len(candidates)))
        issues: list[ConversionIssue] = []
        if not self._conversion.common_policy.dialer_proxy:
            return retained, issues
        counts = Counter(node.name for node in candidates if isinstance(node.name, str))
        dependents: dict[str, list[int]] = defaultdict(list)
        for index, node in enumerate(candidates):
            if isinstance(node.dialer_proxy, str) and node.dialer_proxy:
                dependents[node.dialer_proxy].append(index)
        # Rejected source nodes can still contain malformed fields from a parser.
        source_names = {node.name for node in source if isinstance(node.name, str)}
        missing = deque(sorted(source_names - counts.keys()))
        while missing:
            for index in dependents.get(missing.popleft(), ()):
                if index not in retained:
                    continue
                retained.remove(index)
                node = candidates[index]
                issues.append(self.issue_for_node(
                    node, IssueSeverity.ERROR,
                    f"Dialer proxy '{node.dialer_proxy}' was not emitted",
                    field="dialer_proxy", code="conversion.missing-dialer-proxy",
                ))
                if isinstance(node.name, str):
                    counts[node.name] -= 1
                    if counts[node.name] == 0:
                        missing.append(node.name)
        return retained, issues

    @staticmethod
    def log_issues(issues: list[ConversionIssue]) -> None:
        for issue in issues:
            if issue.code.startswith("ruleset."):
                location = (
                    f"Ruleset '{issue.source}'" if issue.source else "Ruleset"
                )
                context = []
                if issue.field:
                    context.append(issue.field)
                if issue.target:
                    context.append(f"target '{issue.target}'")
                if context:
                    location += f" ({', '.join(context)})"
            elif issue.node:
                location = f"Node '{issue.node}'"
            elif issue.source:
                location = f"Source '{issue.source}'"
            else:
                location = "Conversion"

            detail = issue.message
            if issue.suggestion:
                detail += f" ({issue.suggestion})"
            message = f"{location}: {detail}"
            if issue.severity == IssueSeverity.ERROR:
                logger.error(message)
            elif issue.severity == IssueSeverity.WARNING:
                logger.warning(message)
            else:
                logger.dim(message)
