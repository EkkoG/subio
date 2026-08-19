from __future__ import annotations

import copy
import re
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
    Protocol.MASQUE.value: {"connect-uri": "uri"},
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
    _move_aliases(normalized, _INPUT_ALIASES["*"], dialect="Stash")
    protocol = str(normalized.get("type", ""))
    _move_aliases(normalized, _INPUT_ALIASES.get(protocol, {}), dialect="Stash")
    if protocol == Protocol.TROJAN.value:
        normalized.setdefault("tls", True)
    if protocol == Protocol.TRUSTTUNNEL.value:
        normalized.setdefault("udp", False)
    if protocol == Protocol.MIERU.value and "transport" in normalized:
        normalized["transport"] = str(normalized["transport"]).upper()
    if protocol == Protocol.TUIC.value and "version" in normalized:
        try:
            version = int(normalized.pop("version"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Stash TUIC version must be 4 or 5") from exc
        if version not in {4, 5}:
            raise ValueError("Stash TUIC version must be 4 or 5")
        inferred = 5 if normalized.get("uuid") or normalized.get("password") else 4
        if version != inferred:
            raise ValueError(
                f"Stash TUIC version {version} does not match its credentials"
            )
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

    if node.type == Protocol.TUIC:
        output["version"] = node.version or (5 if output.get("uuid") else 4)

    if node.type == Protocol.MIERU and "transport" in output:
        output["transport"] = str(output["transport"]).lower()

    if node.type == Protocol.MASQUE and node.transport == "h3":
        output.setdefault("network", "h3")

    if node.type == Protocol.HYSTERIA:
        for source, target in (("up", "up-speed"), ("down", "down-speed")):
            if source not in output:
                continue
            value = _mbps_value(output.pop(source))
            if target in output or value is None:
                dropped.add(source)
            else:
                output[target] = value

    if node.type == Protocol.HYSTERIA2:
        for key in ("up-speed", "down-speed"):
            if key not in output:
                continue
            value = _mbps_value(output[key])
            if value is None:
                output.pop(key)
                dropped.add(key)
            else:
                output[key] = value

    if node.type == Protocol.SHADOWSOCKS and isinstance(
        output.get("plugin-opts"), dict
    ):
        source_context = node.source_context
        if source_context is None or source_context.dialect != "stash":
            supported = _PLUGIN_FIELDS.get(str(output.get("plugin")), frozenset())
            options = output["plugin-opts"]
            for key in tuple(options):
                if key not in supported:
                    options.pop(key)
                    dropped.add(f"plugin-opts.{key}")
            if not options:
                output.pop("plugin-opts")

    import subio_v2.protocols as protocol_registry

    codec = protocol_registry.get(node.type)
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
