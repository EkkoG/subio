"""Workflow-owned, secret-safe values exposed to artifact templates."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from subio_v2.core.nodes import Node
from subio_v2.core.results import EmissionFragments
from subio_v2.workflow.selectors import SelectorEngine


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
    _selector_engine: SelectorEngine

    def render(self) -> str:
        return self._rendered

    def _selected(
        self,
        selector: str | None = None,
        *,
        include: str | None = None,
        exclude: str | None = None,
        protocols: Sequence[str] | None = None,
        providers: Sequence[str] | None = None,
    ) -> list[TemplateNodeSummary]:
        return self._selector_engine.select(
            self._summaries,
            selector,
            include=include,
            exclude=exclude,
            protocols=protocols,
            providers=providers,
        )

    def names(
        self,
        selector: str | None = None,
        *,
        include: str | None = None,
        exclude: str | None = None,
        protocols: Sequence[str] | None = None,
        providers: Sequence[str] | None = None,
        prepend: Sequence[str] | None = None,
        fallback: Sequence[str] | None = None,
    ) -> list[str]:
        summaries = self._selected(
            selector,
            include=include,
            exclude=exclude,
            protocols=protocols,
            providers=providers,
        )
        names = [summary.name for summary in summaries]
        if not names and fallback is not None:
            return list(fallback)
        if prepend:
            return [*prepend, *names]
        return names

    def count(
        self,
        selector: str | None = None,
        *,
        include: str | None = None,
        exclude: str | None = None,
        protocols: Sequence[str] | None = None,
        providers: Sequence[str] | None = None,
    ) -> int:
        return len(
            self._selected(
                selector,
                include=include,
                exclude=exclude,
                protocols=protocols,
                providers=providers,
            )
        )

    def exists(
        self,
        selector: str | None = None,
        *,
        include: str | None = None,
        exclude: str | None = None,
        protocols: Sequence[str] | None = None,
        providers: Sequence[str] | None = None,
    ) -> bool:
        return bool(
            self._selected(
                selector,
                include=include,
                exclude=exclude,
                protocols=protocols,
                providers=providers,
            )
        )

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
    selector_engine: SelectorEngine,
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
    node_set = TemplateNodeSet(
        rendered, summaries, platform, fragments, selector_engine
    )
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
