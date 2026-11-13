from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    SingBoxCodecError,
    _keys,
    _optional_string,
    _string_list,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    SSHNode,
)


def _parse_ssh(data: dict[str, Any]) -> dict[str, Any]:
    private_key = data.get("private_key")
    if private_key is not None and not isinstance(private_key, str):
        raise SingBoxCodecError(
            "private_key",
            "SSH private_key arrays are not supported",
            "parse.singbox.unsupported-field",
        )
    host_key = None
    if "host_key" in data:
        host_key = _string_list(data["host_key"], "host_key")
    algorithms = None
    if "host_key_algorithms" in data:
        algorithms = _string_list(data["host_key_algorithms"], "host_key_algorithms")
    return {
        "username": _optional_string(data, "user") or "",
        "password": _optional_string(data, "password"),
        "private_key": private_key,
        "private_key_passphrase": _optional_string(data, "private_key_passphrase"),
        "host_key": host_key,
        "host_key_algorithms": algorithms,
    }


def _emit_ssh(out: dict[str, Any], node: Node) -> None:
    out["user"] = node.username
    if node.password:
        out["password"] = node.password
    if node.private_key:
        out["private_key"] = node.private_key
    if node.private_key_passphrase:
        out["private_key_passphrase"] = node.private_key_passphrase
    if node.host_key:
        out["host_key"] = list(node.host_key)
    if node.host_key_algorithms:
        out["host_key_algorithms"] = list(node.host_key_algorithms)


CODEC = SingBoxOutboundCodec(
    "ssh",
    Protocol.SSH,
    SSHNode,
    _keys(
        "user",
        "password",
        "private_key",
        "private_key_passphrase",
        "host_key",
        "host_key_algorithms",
    ),
    _keys(
        "username",
        "password",
        "private_key",
        "private_key_passphrase",
        "host_key",
        "host_key_algorithms",
    ),
    parse_fields=_parse_ssh,
    emit_fields=_emit_ssh,
    tcp_only=True,
)
