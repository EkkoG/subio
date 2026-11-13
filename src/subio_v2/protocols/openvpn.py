from __future__ import annotations

from subio_v2.core.nodes import Node, OpenVPNNode, Protocol
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec

_PROTOS = {"udp", "udp4", "tcp", "tcp-client", "tcp4", "tcp4-client"}


_DEVICES = {"tun"}


_CIPHERS = {
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


def _validate(node: Node) -> list[NodeValidationError]:
    errors: list[NodeValidationError] = []
    if not isinstance(node, OpenVPNNode):
        return errors

    _validate_enum(errors, "proto", node.proto, _PROTOS)
    _validate_enum(errors, "dev", node.dev, _DEVICES)
    _validate_enum(errors, "cipher", node.cipher, _CIPHERS)
    _validate_enum(errors, "auth", node.auth, _AUTH_METHODS)
    _validate_enum(errors, "comp_lzo", node.comp_lzo, _COMP_LZO_MODES)
    if node.key_direction is not None:
        _validate_enum(errors, "key_direction", node.key_direction, _KEY_DIRECTIONS)

    if node.data_ciphers is not None:
        if not isinstance(node.data_ciphers, list):
            errors.append(
                NodeValidationError(
                    "data_ciphers", "OpenVPN data-ciphers must be a list"
                )
            )
        else:
            unsupported = [
                cipher for cipher in node.data_ciphers if not isinstance(cipher, str)
            ]
            if unsupported:
                errors.append(
                    NodeValidationError(
                        "data_ciphers", "OpenVPN data-ciphers must contain strings"
                    )
                )

    if node.data_ciphers_fallback is not None and (
        not isinstance(node.data_ciphers_fallback, str)
    ):
        errors.append(
            NodeValidationError(
                "data_ciphers_fallback",
                "OpenVPN data-ciphers fallback must be a string",
            )
        )

    has_certificate = node.certificate is not None and node.certificate != ""
    has_private_key = node.private_key is not None and node.private_key != ""
    if has_certificate != has_private_key:
        errors.append(
            NodeValidationError(
                "certificate",
                "OpenVPN cert and key must be configured together",
            )
        )
    if not (has_certificate and has_private_key) and (
        node.username is None or node.username == ""
    ):
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
        if value is not None and value != ""
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
        errors.append(NodeValidationError("dns_servers", "OpenVPN dns must be a list"))
    return errors


def _validate_enum(
    errors: list[NodeValidationError],
    field: str,
    value: str,
    supported: set[str],
) -> None:
    if not isinstance(value, str) or value not in supported:
        errors.append(
            NodeValidationError(
                field,
                f"Unsupported OpenVPN {field.replace('_', '-')}: {value}",
            )
        )


SPEC = ProtocolSpec(
    protocol=Protocol.OPENVPN,
    required_fields=("ca",),
    validator=_validate,
    node_class=OpenVPNNode,
    user_override_fields=frozenset(
        {"server", "port", "username", "password", "auth", "cipher", "private_key"}
    ),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset(
        {
            "auth",
            "ca",
            "certificate",
            "cipher",
            "comp_lzo",
            "data_ciphers",
            "data_ciphers_fallback",
            "dev",
            "dns_servers",
            "handshake_timeout",
            "key_direction",
            "mtu",
            "password",
            "peer_info",
            "ping",
            "ping_restart",
            "private_key",
            "proto",
            "remote_dns_resolve",
            "smux",
            "tls_auth",
            "tls_crypt",
            "tls_crypt_v2",
            "username",
        }
    ),
)
