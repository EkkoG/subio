from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


ParameterValue = str | int | bool
_TOKEN = re.compile(r"{{\s*params\.([A-Za-z_][A-Za-z0-9_]{0,63})\s*}}")
_PARAMS_START = re.compile(r"{{\s*params\b")
MAX_DOCUMENT_DEPTH = 64
MAX_DOCUMENT_VISITS = 100_000
MAX_DOCUMENT_STRING_BYTES = 16 * 1024 * 1024


class MissingParameterError(ValueError):
    """A referenced rendering parameter has neither a request value nor a default."""


def bind_document_parameters(
    data: Any, node_key: str, parameters: Mapping[str, ParameterValue]
) -> Any:
    """Copy a decoded document and bind original scalar occurrences once."""
    visits = 0
    string_bytes = 0

    def account_string(size: int) -> None:
        nonlocal string_bytes
        string_bytes += size
        if string_bytes > MAX_DOCUMENT_STRING_BYTES:
            raise ValueError("Parameterized provider document exceeds the string byte limit")

    def bind_scalar(value: str, allowed: bool) -> ParameterValue:
        matches = list(_TOKEN.finditer(value))
        if _PARAMS_START.search(_TOKEN.sub("", value)):
            raise ValueError("Malformed provider parameter placeholder")
        if not matches:
            account_string(len(value.encode("utf-8")))
            return value
        if not allowed:
            raise ValueError("Provider parameters are only allowed in node scalar values")
        for match in matches:
            if match[1] not in parameters:
                raise MissingParameterError("Missing rendering parameter")
        if len(matches) == 1 and matches[0].span() == (0, len(value)):
            replacement = parameters[matches[0][1]]
            if type(replacement) not in (str, int, bool):
                raise ValueError("Provider parameters must be scalar values")
            if isinstance(replacement, str):
                account_string(len(replacement.encode("utf-8")))
            return replacement
        if any(type(parameters[match[1]]) is not str for match in matches):
            raise ValueError("Embedded provider parameters must be strings")
        size = len(value.encode("utf-8")) + sum(
            len(parameters[match[1]].encode("utf-8")) - len(match[0].encode("utf-8"))
            for match in matches
        )
        account_string(size)
        return _TOKEN.sub(lambda match: parameters[match[1]], value)

    def visit(
        value: Any, allowed: bool, ancestors: frozenset[int], depth: int,
        *, root: bool = False,
    ) -> Any:
        nonlocal visits
        visits += 1
        if visits > MAX_DOCUMENT_VISITS:
            raise ValueError("Parameterized provider document exceeds the visit limit")
        if isinstance(value, tuple):
            # Safe YAML pairs/omap decode to tuples without a faithful output contract.
            raise ValueError("Unsupported tuple in parameterized provider document")
        if isinstance(value, (dict, list, set)):
            depth += 1
            if depth > MAX_DOCUMENT_DEPTH:
                raise ValueError("Parameterized provider document exceeds the depth limit")
            identity = id(value)
            if identity in ancestors:
                raise ValueError("Cyclic parameterized provider document")
            ancestors = ancestors | {identity}
            # No memo: YAML aliases expand independently at every visible path.
            if isinstance(value, list):
                return [visit(item, allowed, ancestors, depth) for item in value]
            if isinstance(value, set):
                # YAML set members are keys and cannot be parameterized.
                return {visit(item, False, ancestors, depth) for item in value}
            copied = {}
            for key, item in value.items():
                visit(key, False, ancestors, depth)
                item_allowed = key == node_key and isinstance(item, list) if root else allowed
                copied[key] = visit(item, item_allowed, ancestors, depth)
            return copied
        if isinstance(value, str):
            return bind_scalar(value, allowed)
        return value

    return visit(data, False, frozenset(), 0, root=isinstance(data, dict))
