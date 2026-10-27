from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


ParameterValue = str | int | bool
_TOKEN = re.compile(r"{{\s*params\.([A-Za-z_][A-Za-z0-9_]{0,63})\s*}}")
_PARAMS_START = re.compile(r"{{\s*params\b")


def bind_document_parameters(
    data: Any, node_key: str, parameters: Mapping[str, ParameterValue]
) -> Any:
    """Copy a decoded document and bind original scalar occurrences once."""

    def bind_scalar(value: str, allowed: bool) -> ParameterValue:
        matches = list(_TOKEN.finditer(value))
        if _PARAMS_START.search(_TOKEN.sub("", value)):
            raise ValueError("Malformed provider parameter placeholder")
        if not matches:
            return value
        if not allowed:
            raise ValueError("Provider parameters are only allowed in node scalar values")
        for match in matches:
            if match[1] not in parameters:
                raise ValueError("Provider parameter has no declared runtime binding")
        if len(matches) == 1 and matches[0].span() == (0, len(value)):
            replacement = parameters[matches[0][1]]
            if type(replacement) not in (str, int, bool):
                raise ValueError("Provider parameters must be scalar values")
            return replacement
        if any(type(parameters[match[1]]) is not str for match in matches):
            raise ValueError("Embedded provider parameters must be strings")
        return _TOKEN.sub(lambda match: parameters[match[1]], value)

    def visit(value: Any, allowed: bool, ancestors: frozenset[int]) -> Any:
        if isinstance(value, tuple):
            # Safe YAML pairs/omap decode to tuples without a faithful output contract.
            raise ValueError("Unsupported tuple in parameterized provider document")
        if isinstance(value, set):
            # YAML sets contain keys, so their members cannot be parameterized.
            return {visit(item, False, ancestors) for item in value}
        if isinstance(value, (dict, list)):
            identity = id(value)
            if identity in ancestors:
                raise ValueError("Cyclic parameterized provider document")
            ancestors = ancestors | {identity}
            # No memo: YAML aliases expand independently at every visible path.
            if isinstance(value, list):
                return [visit(item, allowed, ancestors) for item in value]
            copied = {}
            for key, item in value.items():
                visit(key, False, ancestors)
                copied[key] = visit(item, allowed, ancestors)
            return copied
        if isinstance(value, str):
            return bind_scalar(value, allowed)
        return value

    if not isinstance(data, dict):
        return visit(data, False, frozenset())
    result = {}
    for key, value in data.items():
        visit(key, False, frozenset({id(data)}))
        result[key] = visit(
            value, key == node_key and isinstance(value, list), frozenset({id(data)})
        )
    return result
