from __future__ import annotations

from typing import Any

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
)
from subio_v2.core.nodes import Node, OpenVPNNode, Protocol
from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.protocols.openvpn import _CIPHERS, SPEC


def _optional_string(value: Any) -> str | None:
    return None if value is None else str(value)


class OpenVPNCodec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.OPENVPN
    clash_type = "openvpn"
    target_constraints = {"mihomo": {"features": {"smux"}}}
    fields = (
        scalar_field("proto", default="udp", emit_policy=EmitPolicy.ALWAYS),
        scalar_field("dev", default="tun", emit_policy=EmitPolicy.ALWAYS),
        scalar_field("cipher", default="AES-128-GCM", emit_policy=EmitPolicy.ALWAYS),
        scalar_field("data-ciphers", "data_ciphers", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "data-ciphers-fallback",
            "data_ciphers_fallback",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field("auth", default="SHA256", emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "comp-lzo", "comp_lzo", default="no", emit_policy=EmitPolicy.ALWAYS
        ),
        scalar_field("ca", default="", emit_policy=EmitPolicy.ALWAYS),
        scalar_field("cert", "certificate", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("key", "private_key", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("tls-auth", "tls_auth", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "key-direction",
            "key_direction",
            decode=_optional_string,
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field("tls-crypt", "tls_crypt", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("tls-crypt-v2", "tls_crypt_v2", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("username", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("password", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("peer-info", "peer_info", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("ping", default=0, emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "ping-restart", "ping_restart", default=0, emit_policy=EmitPolicy.ALWAYS
        ),
        scalar_field(
            "handshake-timeout",
            "handshake_timeout",
            default=0,
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field("mtu", default=1500, emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "remote-dns-resolve",
            "remote_dns_resolve",
            default=False,
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field("dns", "dns_servers", emit_policy=EmitPolicy.NOT_NONE),
        smux_group(),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if (
            not isinstance(node, OpenVPNNode)
            or node.data_ciphers is None
            or not isinstance(node.data_ciphers, list)
        ):
            return []
        unsupported = [cipher for cipher in node.data_ciphers if cipher not in _CIPHERS]
        if not unsupported:
            return []
        return [
            IssueDraft(
                IssueSeverity.ERROR,
                "Unsupported OpenVPN data cipher(s): "
                + ", ".join(map(str, unsupported)),
                "data_ciphers",
            )
        ]


CODEC = OpenVPNCodec()
