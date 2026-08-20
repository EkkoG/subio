"""Workflow-owned, secret-safe values exposed to artifact templates."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from subio_v2.core.nodes import Node
from subio_v2.core.results import EmissionFragments


@dataclass(frozen=True)
class TemplateNodeSummary:
    """The non-sensitive node fields needed for template composition."""

    name: str
    protocol: str
    source_provider: str | None
    original_name: str | None
    dialer_proxy: str | None


@dataclass(frozen=True)
class TemplateNodeSet:
    """Read-only node view backed by the target emitter's successful output."""

    _rendered: str
    _summaries: tuple[TemplateNodeSummary, ...]
    _platform: str
    _fragments: EmissionFragments

    def render(self) -> str:
        return self._rendered

    def names(self) -> list[str]:
        return [summary.name for summary in self._summaries]

    def count(self) -> int:
        return len(self._summaries)

    def exists(self) -> bool:
        return bool(self._summaries)

    def legacy_names(self) -> list[str] | str:
        names = self.names()
        if self._platform == "surge":
            return f"PROXY = select, {', '.join(names)}"
        if self._platform == "dae":
            return ", ".join(f"'{name}'" for name in names)
        return names


def build_template_context(
    *,
    platform: str,
    rendered: str,
    nodes: Sequence[Node],
    fragments: EmissionFragments,
) -> dict[str, Any]:
    """Build legacy variables and the new node API in one place."""

    summaries = tuple(
        TemplateNodeSummary(
            name=node.name,
            protocol=node.type.value,
            source_provider=node.source_provider,
            original_name=node.original_name,
            dialer_proxy=node.dialer_proxy,
        )
        for node in nodes
    )
    node_set = TemplateNodeSet(rendered, summaries, platform, fragments)
    context: dict[str, Any] = {
        "nodes": node_set,
        "proxies": rendered,
        "proxies_names": node_set.legacy_names(),
    }
    if fragments.subscription is not None:
        context["subscription"] = fragments.subscription
    if fragments.plain_list is not None:
        context["list"] = fragments.plain_list
    return context
