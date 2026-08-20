from dataclasses import dataclass
from typing import Any, Mapping

from subio_v2.formats import normalize_format


@dataclass(frozen=True)
class DialectContext:
    """Describe the source or target dialect at a conversion boundary."""

    dialect: str
    format: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.dialect, str) or not self.dialect:
            raise ValueError("Dialect name must be a non-empty string")
        if self.format is not None and (
            not isinstance(self.format, str) or not self.format
        ):
            raise ValueError("Dialect format must be a non-empty string")
_PLATFORM_DIALECTS = {
    "mihomo": "mihomo",
    "clash": "clash",
    "stash": "stash",
    "surge": "surge",
    "dae": "dae",
    "v2rayn": "v2rayn",
}


def dialect_context_for_platform(platform: str) -> DialectContext:
    platform = normalize_format(platform)
    dialect = _PLATFORM_DIALECTS.get(platform, platform)
    format_name = "yaml" if platform in {"mihomo", "clash", "stash"} else "text"
    return DialectContext(dialect=dialect, format=format_name)


def extension_semantic_fields(extension: Mapping[str, Any]) -> tuple[str, ...]:
    """Return source-only semantic fields without exposing attachment metadata."""
    fields = {
        str(field)
        for field in extension.get("semantic_fields", [])
        if isinstance(field, str) and field
    }
    parameters = extension.get("parameters", [])
    if isinstance(parameters, list):
        for item in parameters:
            if (
                isinstance(item, (list, tuple))
                and item
                and isinstance(item[0], str)
                and item[0]
            ):
                fields.add(item[0])
    return tuple(sorted(fields))
