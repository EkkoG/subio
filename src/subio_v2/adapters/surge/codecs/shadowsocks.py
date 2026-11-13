from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    SurgeProtocolParseContext,
    _server_str,
)
from subio_v2.adapters.surge.validation import (
    _error,
    _validate_node_obfs_uri,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    ShadowsocksNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_shadowsocks(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    plugin = "obfs" if values.get("obfs") else None
    plugin_opts = (
        {
            "mode": values["obfs"],
            "host": values.get("obfs-host", ""),
        }
        if plugin
        else None
    )
    return ShadowsocksNode(
        name=context.record.name,
        type=Protocol.SHADOWSOCKS,
        server=context.server,
        port=context.port,
        cipher=values.get("encrypt-method") or "chacha20-ietf-poly1305",
        password=values.get("password") or "",
        udp_port=context.get_int("udp-port"),
        plugin=plugin,
        plugin_opts=plugin_opts,
        udp=context.get_bool("udp-relay", False),
        obfs_uri=values.get("obfs-uri"),
    )


def check_shadowsocks(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, ShadowsocksNode):
        return []
    warnings: list[IssueDraft] = []
    supported_ciphers = proto_caps.get("ciphers", set())
    if node.cipher and node.cipher not in supported_ciphers:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Cipher '{node.cipher}' is not supported by surge",
                field="cipher",
                suggestion=f"Supported ciphers: {', '.join(sorted(supported_ciphers))}",
            )
        )
    if node.cipher == "none":
        pass
    elif not node.password:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Shadowsocks password is required for this cipher",
                field="password",
            )
        )
    elif node.cipher.startswith("2022-blake3-aes-"):
        expected = 16 if "128" in node.cipher else 32
        try:
            decoded_keys = [
                base64.b64decode(key, validate=True) for key in node.password.split(":")
            ]
        except (binascii.Error, ValueError):
            decoded_keys = []
        if not decoded_keys or any(
            (len(decoded) != expected for decoded in decoded_keys)
        ):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"{node.cipher} requires each colon-separated base64 key to encode {expected} bytes",
                    field="password",
                )
            )
    if node.plugin:
        supported_plugins = proto_caps.get("plugins", set())
        if node.plugin not in supported_plugins:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Plugin '{node.plugin}' is not supported by surge",
                    field="plugin",
                    suggestion=f"Supported plugins: {', '.join(sorted(supported_plugins))}"
                    if supported_plugins
                    else "No plugins supported",
                )
            )
    return warnings


def emit_shadowsocks(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, ShadowsocksNode)
    parts = ["ss", _server_str(node), str(node.port), f"encrypt-method={node.cipher}"]
    if node.password or node.cipher != "none":
        parts.append(f"password={node.password}")
    if node.udp_port is not None:
        parts.append(f"udp-port={node.udp_port}")
    if node.plugin == "obfs":
        mode = node.plugin_opts.get("mode", "http") if node.plugin_opts else "http"
        parts.append(f"obfs={mode}")
        host = node.plugin_opts.get("host", "") if node.plugin_opts else ""
        if host:
            parts.append(f"obfs-host={host}")
        if node.obfs_uri:
            parts.append(f"obfs-uri={node.obfs_uri}")
    return parts


def validate_shadowsocks_fields(node: ShadowsocksNode) -> list[IssueDraft]:
    errors: list[IssueDraft] = []
    if node.udp_port is not None and (
        not isinstance(node.udp_port, int)
        or isinstance(node.udp_port, bool)
        or not 1 <= node.udp_port <= 65535
    ):
        errors.append(_error("udp_port must be between 1 and 65535", "udp_port"))
    obfs_mode = None
    if node.plugin == "obfs" and isinstance(node.plugin_opts, Mapping):
        obfs_mode = node.plugin_opts.get("mode")
    elif node.plugin:
        obfs_mode = node.plugin
    _validate_node_obfs_uri(node.obfs_uri, obfs_mode, errors)
    return errors


CODECS = (
    _spec(
        "ss",
        protocol=Protocol.SHADOWSOCKS,
        precheck=validate_shadowsocks_fields,
        check=check_shadowsocks,
        udp=SurgeUdpBehavior.EXPLICIT,
        parser=parse_shadowsocks,
        emitter=emit_shadowsocks,
        consumed=(
            "encrypt-method",
            "password",
            "udp-relay",
            "udp-port",
            "obfs",
            "obfs-host",
            "obfs-uri",
        ),
        constraints={
            "ciphers": {
                "2022-blake3-aes-128-gcm",
                "2022-blake3-aes-256-gcm",
                "aes-128-cfb",
                "aes-128-ctr",
                "aes-128-gcm",
                "aes-192-cfb",
                "aes-192-ctr",
                "aes-192-gcm",
                "aes-256-cfb",
                "aes-256-ctr",
                "aes-256-gcm",
                "chacha20",
                "chacha20-ietf",
                "chacha20-ietf-poly1305",
                "none",
                "rc4",
                "rc4-md5",
                "salsa20",
                "xchacha20-ietf-poly1305",
            },
            "plugins": {"obfs"},
        },
    ),
)
