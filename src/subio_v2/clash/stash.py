from __future__ import annotations

import copy
import re
from typing import Any

import subio_v2.protocols as protocol_registry
from subio_v2.model.nodes import Node, Protocol

_COMMON_INPUT_ALIASES = {"server-cert-fingerprint": "fingerprint"}
_COMMON_OUTPUT_ALIASES = {"fingerprint": "server-cert-fingerprint"}

_UNSUPPORTED_COMMON_FIELDS = frozenset(
    {
        "certificate",
        "mptcp",
        "name-cert-verify",
        "routing-mark",
        "users",
    }
)

_PLUGIN_FIELDS = {
    "obfs": frozenset({"mode", "host"}),
    "v2ray-plugin": frozenset(
        {"mode", "tls", "skip-cert-verify", "host", "path", "headers"}
    ),
    "shadow-tls": frozenset(
        {"password", "host", "skip-cert-verify", "version"}
    ),
}


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


def _mbps_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    match = re.fullmatch(r"\s*(\d+)\s*(?:Mbps)?\s*", str(value), re.IGNORECASE)
    return int(match.group(1)) if match else None


def normalize_stash_proxy(data: dict[str, Any]) -> dict[str, Any]:
    """Translate documented Stash aliases into the shared codec dialect."""
    normalized = copy.deepcopy(data)
    _move_aliases(normalized, _COMMON_INPUT_ALIASES, dialect="Stash")
    protocol = str(normalized.get("type", ""))
    codec = protocol_registry.by_clash_type(protocol)
    if codec is None:
        return normalized
    _move_aliases(normalized, dict(codec.stash_input_aliases), dialect="Stash")
    return codec.normalize_stash(normalized)


def post_stash_emit(
    data: dict[str, Any], node: Node
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Translate shared fields to Stash names and trim unsupported common fields."""
    output = copy.deepcopy(data)
    dropped = {key for key in _UNSUPPORTED_COMMON_FIELDS if key in output}
    for key in dropped:
        output.pop(key, None)

    _move_aliases(output, _COMMON_OUTPUT_ALIASES, dialect="shared")
    codec = protocol_registry.get(node.type)
    if codec is not None:
        _move_aliases(output, dict(codec.stash_output_aliases), dialect="shared")
    if "servername" in output:
        if "sni" in output and output["sni"] != output["servername"]:
            raise ValueError("Conflicting shared fields 'servername' and 'sni'")
        output["sni"] = output.pop("servername")

    if codec is not None:
        output, codec_dropped = codec.post_stash_emit(output, node)
        dropped.update(codec_dropped)
    allowed = set(codec.fields_for_dialect("stash") if codec else frozenset())
    if node.source_context is not None and node.source_context.dialect == "stash":
        allowed.update(node.extra)
    for key in tuple(output):
        if key not in allowed:
            lossless_default = (
                node.type == Protocol.TAILSCALE
                and output[key] is False
                and key
                in {"udp", "accept-routes", "exit-node-allow-lan-access"}
            ) or (
                node.type == Protocol.MASQUE
                and output[key] is False
                and key in {"udp", "remote-dns-resolve"}
            ) or (
                node.type == Protocol.TRUSTTUNNEL
                and key == "udp"
                and output[key] is False
            )
            output.pop(key)
            if not lossless_default and not (
                key == "udp"
                and node.type
                in {Protocol.SSH, Protocol.DIRECT, Protocol.MIERU, Protocol.JUICITY}
                and node.udp
            ):
                dropped.add(key)
    return output, tuple(sorted(dropped))
