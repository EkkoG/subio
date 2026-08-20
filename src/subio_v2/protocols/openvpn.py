from __future__ import annotations

from typing import Any

from subio_v2.core.nodes import Node, OpenVPNNode, Protocol
from subio_v2.protocols._base import NodeValidationError, StructuredClashProtocolCodec
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.OPENVPN,
    node_class=OpenVPNNode,
    user_override_fields=frozenset({"server", "port", "username", "password", "auth", "cipher", "private_key"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_fields=frozenset({"auth", "ca", "certificate", "cipher", "comp_lzo", "data_ciphers", "data_ciphers_fallback", "dev", "dns_servers", "handshake_timeout", "key_direction", "mtu", "password", "peer_info", "ping", "ping_restart", "private_key", "proto", "remote_dns_resolve", "smux", "tls_auth", "tls_crypt", "tls_crypt_v2", "username"}),
)

_PROTOS = {"udp", "udp4", "tcp", "tcp-client", "tcp4", "tcp4-client"}
_DEVICES = {"tun"}
_DATA_CIPHERS = {
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "AES-CBC",
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
    "CHACHA20-POLY1305",
}
_AUTH_METHODS = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
_COMP_LZO_MODES = {"yes", "no", "adaptive"}
_KEY_DIRECTIONS = {"0", "1"}


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
        scalar_field(
            "data-ciphers", "data_ciphers", emit_policy=EmitPolicy.NOT_NONE
        ),
        scalar_field(
            "data-ciphers-fallback",
            "data_ciphers_fallback",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field("auth", default="SHA256", emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "comp-lzo", "comp_lzo", default="no", emit_policy=EmitPolicy.ALWAYS
        ),
        scalar_field("ca", default="", emit_policy=EmitPolicy.ALWAYS, required=True),
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
        scalar_field(
            "tls-crypt-v2", "tls_crypt_v2", emit_policy=EmitPolicy.NOT_NONE
        ),
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

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = super().validate(node)
        if not isinstance(node, OpenVPNNode):
            return errors

        self._validate_enum(errors, "proto", node.proto, _PROTOS)
        self._validate_enum(errors, "dev", node.dev, _DEVICES)
        self._validate_enum(errors, "cipher", node.cipher, _DATA_CIPHERS)
        self._validate_enum(errors, "auth", node.auth, _AUTH_METHODS)
        self._validate_enum(errors, "comp_lzo", node.comp_lzo, _COMP_LZO_MODES)
        if node.key_direction is not None:
            self._validate_enum(
                errors, "key_direction", node.key_direction, _KEY_DIRECTIONS
            )

        if node.data_ciphers is not None:
            if not isinstance(node.data_ciphers, list):
                errors.append(
                    NodeValidationError(
                        "data_ciphers", "OpenVPN data-ciphers must be a list"
                    )
                )
            else:
                unsupported = [
                    cipher for cipher in node.data_ciphers if cipher not in _DATA_CIPHERS
                ]
                if unsupported:
                    errors.append(
                        NodeValidationError(
                            "data_ciphers",
                            "Unsupported OpenVPN data cipher(s): "
                            + ", ".join(map(str, unsupported)),
                        )
                    )

        has_certificate = node.certificate not in {None, ""}
        has_private_key = node.private_key not in {None, ""}
        if has_certificate != has_private_key:
            errors.append(
                NodeValidationError(
                    "certificate",
                    "OpenVPN cert and key must be configured together",
                )
            )
        if not (has_certificate and has_private_key) and node.username in {None, ""}:
            errors.append(
                NodeValidationError(
                    "username",
                    "OpenVPN username is required when cert/key are not configured",
                )
            )

        static_keys = [
            field
            for field, value in (
                ("tls_auth", node.tls_auth),
                ("tls_crypt", node.tls_crypt),
                ("tls_crypt_v2", node.tls_crypt_v2),
            )
            if value not in {None, ""}
        ]
        if len(static_keys) > 1:
            errors.append(
                NodeValidationError(
                    "tls_auth",
                    "OpenVPN tls-auth, tls-crypt, and tls-crypt-v2 are mutually exclusive",
                )
            )
        if node.peer_info is not None and not isinstance(node.peer_info, dict):
            errors.append(
                NodeValidationError("peer_info", "OpenVPN peer-info must be a mapping")
            )
        if node.dns_servers is not None and not isinstance(node.dns_servers, list):
            errors.append(
                NodeValidationError("dns_servers", "OpenVPN dns must be a list")
            )
        return errors

    @staticmethod
    def _validate_enum(
        errors: list[NodeValidationError],
        field: str,
        value: str,
        supported: set[str],
    ) -> None:
        if value not in supported:
            errors.append(
                NodeValidationError(
                    field,
                    f"Unsupported OpenVPN {field.replace('_', '-')}: {value}",
                )
            )


CODEC = OpenVPNCodec()
