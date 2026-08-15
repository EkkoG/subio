from __future__ import annotations

import copy
from typing import Any

from subio_v2.model.nodes import Node, Protocol


_INPUT_ALIASES: dict[str, dict[str, str]] = {
    "*": {"server-cert-fingerprint": "fingerprint"},
    Protocol.SSH.value: {"user": "username"},
    Protocol.HYSTERIA2.value: {
        "auth": "password",
        "up-speed": "up",
        "down-speed": "down",
    },
    Protocol.WIREGUARD.value: {"keepalive": "persistent-keepalive"},
}

_OUTPUT_ALIASES = {
    source: {target: source for source, target in aliases.items()}
    for source, aliases in _INPUT_ALIASES.items()
}

_UNSUPPORTED_COMMON_FIELDS = frozenset(
    {
        "certificate",
        "mptcp",
        "name-cert-verify",
        "routing-mark",
        "users",
    }
)


def _move_aliases(
    data: dict[str, Any], aliases: dict[str, str], *, dialect: str
) -> None:
    for source, target in aliases.items():
        if source not in data:
            continue
        if target in data and data[target] != data[source]:
            raise ValueError(
                f"Conflicting {dialect} fields '{source}' and '{target}'"
            )
        data[target] = data.pop(source)


def normalize_stash_proxy(data: dict[str, Any]) -> dict[str, Any]:
    """Translate documented Stash aliases into the shared descriptor dialect."""
    normalized = copy.deepcopy(data)
    _move_aliases(normalized, _INPUT_ALIASES["*"], dialect="Stash")
    protocol = str(normalized.get("type", ""))
    _move_aliases(normalized, _INPUT_ALIASES.get(protocol, {}), dialect="Stash")
    return normalized


def post_stash_emit(
    data: dict[str, Any], node: Node
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Translate shared fields to Stash names and trim unsupported common fields."""
    output = copy.deepcopy(data)
    dropped = {key for key in _UNSUPPORTED_COMMON_FIELDS if key in output}
    for key in dropped:
        output.pop(key, None)

    _move_aliases(output, _OUTPUT_ALIASES["*"], dialect="shared")
    _move_aliases(
        output, _OUTPUT_ALIASES.get(node.type.value, {}), dialect="shared"
    )
    if "servername" in output:
        if "sni" in output and output["sni"] != output["servername"]:
            raise ValueError("Conflicting shared fields 'servername' and 'sni'")
        output["sni"] = output.pop("servername")
    return output, tuple(sorted(dropped))
