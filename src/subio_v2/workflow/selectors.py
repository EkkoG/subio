"""Deterministic, data-only node selectors shared by workflow and templates."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from subio_v2.core.errors import ConfigError

_SORT_FIELDS = frozenset(
    {"source_order", "name", "protocol", "source_provider"}
)


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, (list, tuple)) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ConfigError(f"{label} must be a string or a list of non-empty strings")
    return tuple(value)


@dataclass(frozen=True)
class SelectorSpec:
    name_regex: tuple[str, ...] = ()
    exclude_name_regex: tuple[str, ...] = ()
    protocols: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()
    all_of: tuple[str, ...] = ()
    any_of: tuple[str, ...] = ()
    not_of: tuple[str, ...] = ()
    sort_by: tuple[str, ...] = ()
    limit: int | None = None
    match_original_name: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SelectorSpec:
        sort_by = _string_tuple(value.get("sort_by"), "Selector sort_by")
        unknown_sort = set(sort_by) - _SORT_FIELDS
        if unknown_sort:
            raise ConfigError(
                "Selector sort_by contains unsupported fields: "
                + ", ".join(sorted(unknown_sort))
            )
        limit = value.get("limit")
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0):
            raise ConfigError("Selector limit must be a positive integer")
        match_original_name = value.get("match_original_name", False)
        if not isinstance(match_original_name, bool):
            raise ConfigError("Selector match_original_name must be a boolean")
        return cls(
            name_regex=_string_tuple(value.get("name_regex"), "Selector name_regex"),
            exclude_name_regex=_string_tuple(
                value.get("exclude_name_regex"), "Selector exclude_name_regex"
            ),
            protocols=_string_tuple(value.get("protocols"), "Selector protocols"),
            providers=_string_tuple(value.get("providers"), "Selector providers"),
            all_of=_string_tuple(value.get("all_of"), "Selector all_of"),
            any_of=_string_tuple(value.get("any_of"), "Selector any_of"),
            not_of=_string_tuple(value.get("not"), "Selector not"),
            sort_by=sort_by,
            limit=limit,
            match_original_name=match_original_name,
        )


def _value(item: Any, field: str) -> str | None:
    if field == "protocol":
        value = getattr(item, "type", None)
        if value is None:
            value = getattr(item, "protocol", None)
        return getattr(value, "value", value)
    value = getattr(item, field, None)
    return value if isinstance(value, str) else None


def validate_selector_graph(references: Mapping[str, Sequence[str]]) -> None:
    active: set[str] = set()
    finished: set[str] = set()
    for root in references:
        if root in finished:
            continue
        active.add(root)
        stack = [(root, iter(references[root]))]
        while stack:
            name, children = stack[-1]
            try:
                ref = next(children)
            except StopIteration:
                active.remove(name)
                finished.add(name)
                stack.pop()
                continue
            if ref not in references:
                raise ConfigError(f"Selector {name!r} references unknown selector {ref!r}")
            if ref in active:
                raise ConfigError(f"Selector reference cycle includes {ref!r}")
            if ref not in finished:
                active.add(ref)
                stack.append((ref, iter(references[ref])))


class SelectorEngine:
    def __init__(self, selectors: Mapping[str, SelectorSpec] | None = None):
        self._selectors = dict(selectors or {})
        self._compiled: dict[str, tuple[re.Pattern[str], ...]] = {}
        self._compiled_exclude: dict[str, tuple[re.Pattern[str], ...]] = {}
        for name, spec in self._selectors.items():
            self._compiled[name], self._compiled_exclude[name] = self._compile_patterns(
                spec, f"Selector {name!r}",
            )
        self._validate_references()

    def select(
        self,
        items: Sequence[Any],
        selector: str | None = None,
        *,
        include: str | None = None,
        exclude: str | None = None,
        protocols: Sequence[str] | None = None,
        providers: Sequence[str] | None = None,
    ) -> list[Any]:
        if selector is not None and selector not in self._selectors:
            raise ConfigError(f"Selector references unknown selector {selector!r}")
        inline = SelectorSpec(
            name_regex=(include,) if include else (),
            exclude_name_regex=(exclude,) if exclude else (),
            protocols=tuple(protocols or ()),
            providers=tuple(providers or ()),
        )
        include_patterns, exclude_patterns = self._compile_patterns(inline, "Inline selector")
        selected = [
            item
            for item in items
            if self._matches_spec(
                item, self._selectors.get(selector), set(), selector
            )
            and self._matches_atomic(item, inline, include_patterns, exclude_patterns)
        ]
        if selector:
            spec = self._selectors[selector]
            selected = self._sort(selected, spec.sort_by)
            if spec.limit is not None:
                selected = selected[: spec.limit]
        return selected

    def _matches_spec(
        self,
        item: Any,
        spec: SelectorSpec | None,
        stack: set[str],
        selector_name: str | None,
    ) -> bool:
        if spec is None:
            return True
        if not self._matches_atomic(
            item, spec, self._compiled.get(selector_name, ()),
            self._compiled_exclude.get(selector_name, ()),
        ):
            return False
        for ref in spec.all_of:
            if not self._matches_named(item, ref, stack):
                return False
        if spec.any_of and not any(
            self._matches_named(item, ref, stack) for ref in spec.any_of
        ):
            return False
        return not any(self._matches_named(item, ref, stack) for ref in spec.not_of)

    def _matches_named(self, item: Any, name: str, stack: set[str]) -> bool:
        if name in stack:
            raise ConfigError(f"Selector reference cycle includes {name!r}")
        if name not in self._selectors:
            raise ConfigError(f"Selector references unknown selector {name!r}")
        return self._matches_spec(item, self._selectors[name], {*stack, name}, name)

    def _matches_atomic(
        self, item: Any, spec: SelectorSpec,
        include: tuple[re.Pattern[str], ...], exclude: tuple[re.Pattern[str], ...],
    ) -> bool:
        selected_name = self._selector_name(item, spec)
        if include and not any(pattern.search(selected_name) for pattern in include):
            return False
        if exclude and any(pattern.search(selected_name) for pattern in exclude):
            return False
        protocol = _value(item, "protocol")
        provider = _value(item, "source_provider")
        if spec.protocols and protocol not in spec.protocols:
            return False
        return not spec.providers or provider in spec.providers

    @staticmethod
    def _compile_patterns(spec: SelectorSpec, label: str):
        try:
            return (
                tuple(re.compile(pattern, re.IGNORECASE) for pattern in spec.name_regex),
                tuple(re.compile(pattern, re.IGNORECASE) for pattern in spec.exclude_name_regex),
            )
        except (re.error, OverflowError, RecursionError) as exc:
            raise ConfigError(f"{label} contains an invalid regex") from exc

    @staticmethod
    def _selector_name(item: Any, spec: SelectorSpec) -> str:
        if spec.match_original_name:
            original = _value(item, "original_name")
            if original is not None:
                return original
        return _value(item, "name") or ""

    def _sort(self, items: list[Any], fields: Sequence[str]) -> list[Any]:
        result = list(enumerate(items))
        for field in reversed(tuple(fields)):
            if field == "source_order":
                result.sort(key=lambda pair: pair[0])
            else:
                result.sort(key=lambda pair: (_value(pair[1], field) or "").casefold())
        return [item for _, item in result]

    def _validate_references(self) -> None:
        validate_selector_graph({
            name: (*spec.all_of, *spec.any_of, *spec.not_of)
            for name, spec in self._selectors.items()
        })


def resolve_duplicate_names(
    items: Sequence[Any], policy: str
) -> tuple[list[Any], tuple[str, ...]]:
    seen: set[str] = set()
    duplicates: list[str] = []
    selected: list[Any] = []
    for item in items:
        name = _value(item, "name") or ""
        if name in seen:
            if name not in duplicates:
                duplicates.append(name)
            if policy == "keep_first":
                continue
        seen.add(name)
        selected.append(item)
    return selected, tuple(duplicates)
