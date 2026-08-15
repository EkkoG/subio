"""Lossless-enough syntax handling for one Surge proxy definition line."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import overload


@dataclass(frozen=True)
class SurgeParameter:
    """One ordered key/value parameter from a Surge proxy line."""

    key: str
    value: str


@dataclass(frozen=True, init=False)
class SurgeParameters(Sequence[SurgeParameter]):
    """Ordered parameters that retain duplicate keys."""

    _entries: tuple[SurgeParameter, ...]

    def __init__(self, entries: Iterable[SurgeParameter] = ()) -> None:
        object.__setattr__(self, "_entries", tuple(entries))

    @overload
    def __getitem__(self, index: int) -> SurgeParameter: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[SurgeParameter, ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> SurgeParameter | tuple[SurgeParameter, ...]:
        return self._entries[index]

    def __iter__(self) -> Iterator[SurgeParameter]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def items(self) -> tuple[tuple[str, str], ...]:
        return tuple((entry.key, entry.value) for entry in self._entries)

    def get_all(self, key: str) -> tuple[str, ...]:
        return tuple(entry.value for entry in self._entries if entry.key == key)

    def get(self, key: str, default: str | None = None) -> str | None:
        for entry in reversed(self._entries):
            if entry.key == key:
                return entry.value
        return default

    @property
    def last_values(self) -> dict[str, str]:
        return {entry.key: entry.value for entry in self._entries}


@dataclass(frozen=True)
class SurgeProxyRecord:
    """Parsed representation of ``name = type, ...``."""

    name: str
    type: str
    positional: tuple[str, ...] = ()
    parameters: SurgeParameters = field(default_factory=SurgeParameters)

    def __post_init__(self) -> None:
        object.__setattr__(self, "positional", tuple(self.positional))
        if not isinstance(self.parameters, SurgeParameters):
            object.__setattr__(self, "parameters", SurgeParameters(self.parameters))


def parse_proxy_line(line: str) -> SurgeProxyRecord:
    """Parse one Surge proxy line while retaining parameter order and duplicates."""

    if not isinstance(line, str):
        raise TypeError("Surge proxy line must be a string")
    if "=" not in line:
        raise ValueError("Surge proxy line must contain '='")

    raw_name, payload = line.split("=", 1)
    name = raw_name.strip()
    if not name:
        raise ValueError("Surge proxy name is required")

    tokens = _split_comma_separated(payload)
    if not tokens or not tokens[0].strip():
        raise ValueError("Surge proxy type is required")

    proxy_type = _decode_atom(tokens[0])
    if not proxy_type:
        raise ValueError("Surge proxy type is required")

    positional: list[str] = []
    parameters: list[SurgeParameter] = []
    for token in tokens[1:]:
        separator = _find_unquoted(token, "=")
        if separator is None:
            positional.append(_decode_atom(token))
            continue

        key = token[:separator].strip()
        if not key:
            raise ValueError("Surge parameter key is required")
        parameters.append(
            SurgeParameter(key=key, value=_decode_atom(token[separator + 1 :]))
        )

    return SurgeProxyRecord(
        name=name,
        type=proxy_type,
        positional=tuple(positional),
        parameters=SurgeParameters(parameters),
    )


def serialize_proxy_line(record: SurgeProxyRecord) -> str:
    """Serialize a proxy record to stable, canonical Surge syntax."""

    if not isinstance(record, SurgeProxyRecord):
        raise TypeError("record must be a SurgeProxyRecord")
    _validate_identity(record.name, record.type)

    tokens = [record.type]
    tokens.extend(
        _encode_atom(value, quote_equals=True, quote_empty=True)
        for value in record.positional
    )
    for parameter in record.parameters:
        _validate_parameter(parameter)
        tokens.append(f"{parameter.key}={_encode_atom(parameter.value)}")
    return f"{record.name} = {', '.join(tokens)}"


def parse_parameter_list(payload: str) -> SurgeParameters:
    """Parse a comma-separated Surge key/value list without losing duplicates."""

    if not isinstance(payload, str):
        raise TypeError("Surge parameter list must be a string")
    entries: list[SurgeParameter] = []
    for token in _split_comma_separated(payload):
        separator = _find_unquoted(token, "=")
        if separator is None:
            raise ValueError("Surge parameter must contain '='")
        key = token[:separator].strip()
        if not key:
            raise ValueError("Surge parameter key is required")
        entries.append(
            SurgeParameter(key=key, value=_decode_atom(token[separator + 1 :]))
        )
    return SurgeParameters(entries)


def serialize_parameter_list(
    parameters: Iterable[SurgeParameter], *, spaced_equals: bool = False
) -> str:
    """Serialize an ordered Surge key/value list using canonical quoting."""

    separator = " = " if spaced_equals else "="
    parts: list[str] = []
    for parameter in parameters:
        _validate_parameter(parameter)
        parts.append(f"{parameter.key}{separator}{_encode_atom(parameter.value)}")
    return ", ".join(parts)


def _split_comma_separated(payload: str) -> tuple[str, ...]:
    tokens: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False

    for char in payload:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if in_quotes and char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            current.append(char)
            in_quotes = not in_quotes
            continue
        if char == "," and not in_quotes:
            tokens.append("".join(current))
            current = []
            continue
        current.append(char)

    if in_quotes:
        raise ValueError("Surge proxy line has an unterminated double quote")
    tokens.append("".join(current))
    return tuple(tokens)


def _find_unquoted(value: str, needle: str) -> int | None:
    in_quotes = False
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if in_quotes and char == "\\":
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            continue
        if char == needle and not in_quotes:
            return index
    return None


def _decode_atom(raw_value: str) -> str:
    value = raw_value.strip()
    if not value.startswith('"'):
        return value

    decoded: list[str] = []
    escaped = False
    closing_index: int | None = None
    for index, char in enumerate(value[1:], start=1):
        if escaped:
            if char in {'"', "\\"}:
                decoded.append(char)
            else:
                decoded.extend(("\\", char))
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            closing_index = index
            break
        decoded.append(char)

    if closing_index is None:
        raise ValueError("Surge value has an unterminated double quote")
    if value[closing_index + 1 :].strip():
        raise ValueError("Unexpected content after quoted Surge value")
    return "".join(decoded)


def _encode_atom(
    value: str, *, quote_equals: bool = False, quote_empty: bool = False
) -> str:
    if not isinstance(value, str):
        raise TypeError("Surge syntax values must be strings")
    if "\n" in value or "\r" in value:
        raise ValueError("Surge syntax values cannot contain newlines")

    needs_quotes = (
        (quote_empty and not value)
        or "," in value
        or '"' in value
        or value != value.strip()
        or (quote_equals and "=" in value)
    )
    if not needs_quotes:
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _validate_identity(name: str, proxy_type: str) -> None:
    if not name:
        raise ValueError("Surge proxy name is required")
    if "=" in name or "\n" in name or "\r" in name:
        raise ValueError("Surge proxy name cannot contain '=' or newlines")
    if not proxy_type:
        raise ValueError("Surge proxy type is required")
    if (
        any(char in proxy_type for char in ',="\n\r')
        or proxy_type != proxy_type.strip()
    ):
        raise ValueError("Surge proxy type contains invalid syntax characters")


def _validate_parameter(parameter: SurgeParameter) -> None:
    if not isinstance(parameter, SurgeParameter):
        raise TypeError("Surge parameters must contain SurgeParameter values")
    if not parameter.key:
        raise ValueError("Surge parameter key is required")
    if (
        parameter.key != parameter.key.strip()
        or any(char in parameter.key for char in ',="\n\r')
        or any(char.isspace() for char in parameter.key)
    ):
        raise ValueError(f"Invalid Surge parameter key: {parameter.key!r}")
