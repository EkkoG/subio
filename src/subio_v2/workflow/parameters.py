from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from subio_v2.core.errors import ConfigError
from subio_v2.core.parameters import ParameterValue


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z", re.ASCII)
_INTEGER = re.compile(r"[+-]?[0-9]+\Z", re.ASCII)
_TYPES = {"string": str, "integer": int, "boolean": bool}


class ParameterError(ValueError):
    """Invalid rendering input; messages never include parameter values."""


class ParameterLimitError(ParameterError):
    pass


def _validate_text(value: str) -> None:
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ParameterError("Rendering parameter is not valid UTF-8") from None
    if size > 1024:
        raise ParameterLimitError("Rendering parameter exceeds the size limit")
    if any(unicodedata.category(char) in {"Cc", "Zl", "Zp"} for char in value):
        raise ParameterError("Rendering parameter contains a forbidden character")


@dataclass(frozen=True)
class ParameterSpec:
    type: str
    default: ParameterValue | None = field(default=None, repr=False)
    choices: tuple[ParameterValue, ...] | None = field(default=None, repr=False)
    min: int | None = None
    max: int | None = None

    @classmethod
    def from_mapping(cls, value: Any) -> ParameterSpec:
        if not isinstance(value, dict) or set(value) - {
            "type", "default", "choices", "min", "max"
        }:
            raise ConfigError("Render parameter declaration must use supported fields")
        parameter_type = value.get("type", "string")
        if not isinstance(parameter_type, str) or parameter_type not in _TYPES:
            raise ConfigError("Render parameter type must be string, integer or boolean")
        for key in ("min", "max"):
            if key in value and (
                parameter_type != "integer" or type(value[key]) is not int
            ):
                raise ConfigError("Render parameter min/max require integer values and type")
        if "min" in value and "max" in value and value["min"] > value["max"]:
            raise ConfigError("Render parameter min cannot exceed max")
        choices = value.get("choices")
        if "choices" in value and (not isinstance(choices, list) or not choices):
            raise ConfigError("Render parameter choices must be a non-empty list")
        spec = cls(
            type=parameter_type,
            default=value.get("default"),
            choices=tuple(choices) if choices is not None else None,
            min=value.get("min"),
            max=value.get("max"),
        )
        try:
            for choice in spec.choices or ():
                spec.validate_value(choice)
            if "default" in value:
                spec.validate_value(spec.default)
        except ParameterError:
            raise ConfigError("Render parameter default or choices violate its declaration") from None
        return spec

    def validate_value(self, value: Any) -> None:
        if type(value) is not _TYPES[self.type]:
            raise ParameterError("Rendering parameter has an invalid type")
        if isinstance(value, str):
            _validate_text(value)
        if self.min is not None and value < self.min:
            raise ParameterError("Rendering parameter is below its minimum")
        if self.max is not None and value > self.max:
            raise ParameterError("Rendering parameter exceeds its maximum")
        if self.choices is not None and value not in self.choices:
            raise ParameterError("Rendering parameter is not an allowed choice")


def parse_parameter_specs(value: Any) -> Mapping[str, ParameterSpec]:
    if not isinstance(value, dict) or len(value) > 32:
        raise ConfigError("Artifact params must be an object with at most 32 entries")
    if any(
        not isinstance(name, str) or not _NAME.fullmatch(name) or name == "token"
        for name in value
    ):
        raise ConfigError("Render parameter names must be ASCII identifiers; token is reserved")
    return MappingProxyType({
        name: ParameterSpec.from_mapping(spec) for name, spec in value.items()
    })


def normalize_parameters(
    declarations: Mapping[str, ParameterSpec], pairs: Iterable[tuple[str, str]]
) -> Mapping[str, ParameterValue]:
    """Normalize decoded rendering pairs after the transport removes auth controls."""
    values: dict[str, ParameterValue] = {}
    for index, (name, raw) in enumerate(pairs):
        if index >= 32:
            raise ParameterLimitError("Too many rendering parameter fields")
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name == "token":
            raise ParameterError("Invalid or reserved rendering parameter name")
        if name in values:
            raise ParameterError("Duplicate rendering parameter")
        if not isinstance(raw, str):
            raise ParameterError("Rendering parameters must be strings")
        _validate_text(raw)
        spec = declarations.get(name)
        if spec is None:
            values[name] = raw
            continue
        if spec.type == "integer":
            if not _INTEGER.fullmatch(raw):
                raise ParameterError("Rendering integer must use signed decimal syntax")
            value: ParameterValue = int(raw)
        elif spec.type == "boolean":
            if raw not in {"true", "false"}:
                raise ParameterError("Rendering boolean must be true or false")
            value = raw == "true"
        else:
            value = raw
        spec.validate_value(value)
        values[name] = value
    for name, spec in declarations.items():
        if name not in values and spec.default is not None:
            values[name] = spec.default
    return MappingProxyType(values)
