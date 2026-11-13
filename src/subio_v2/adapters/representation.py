"""Format-owned presentation of successful node output to templates."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


def _text(content: str | dict[str, Any], template: bool) -> str:
    return content


def _unavailable_fragment(rendered: str, key: str) -> str:
    raise ValueError(f"nodes.{key}() is only available for sing-box templates")


@dataclass(frozen=True)
class FormatRepresentation:
    serialize: Callable[[str | dict[str, Any], bool], str] = _text
    legacy_names: Callable[[list[str]], list[str] | str] = lambda names: names
    fragment: Callable[[str, str], str] = _unavailable_fragment
    validate_template: Callable[[str, str], None] = lambda content, path: None
