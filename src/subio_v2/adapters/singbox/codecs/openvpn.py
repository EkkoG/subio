from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxEndpointCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _COMMON_KEYS,
    _ROUTING_MARK_MAX,
    SingBoxCodecError,
    _common_kwargs,
    _optional_enum_string,
    _optional_int,
    _optional_string,
    _required_string,
    _string_or_list,
    unsupported_field_code,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _ENDPOINT_COMMON_NODE_FIELDS as _COMMON_NODE_FIELDS,
)
from subio_v2.core.nodes import (
    Node,
    OpenVPNNode,
    Protocol,
)

_OPENVPN_KEYS = _COMMON_KEYS | frozenset(
    {
        "server",
        "server_port",
        "mode",
        "network",
        "username",
        "password",
        "tls",
        "data_ciphers",
        "data_ciphers_fallback",
        "auth",
        "compression_lzo",
        "mtu",
    }
)


_OPENVPN_TLS_KEYS = frozenset({"certificate", "client_certificate", "client_key"})


_OPENVPN_NETWORKS = frozenset({"udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"})


_OPENVPN_NETWORK_TO_PROTO = {
    "udp": "udp",
    "udp4": "udp4",
    "tcp": "tcp-client",
    "tcp4": "tcp4-client",
}


_OPENVPN_PROTO_TO_NETWORK = {
    value: key for key, value in _OPENVPN_NETWORK_TO_PROTO.items()
}


_OPENVPN_AUTH_METHODS = frozenset({"MD5", "SHA1", "SHA256", "SHA384", "SHA512"})


_OPENVPN_COMPRESSION_LZO = frozenset({"no", "yes", "adaptive"})


_OPENVPN_STREAM_CIPHER_BASES = frozenset(
    {
        "BF",
        "DES",
        "DES-EDE",
        "DES-EDE3",
        "CAST5",
        "AES-128",
        "AES-192",
        "AES-256",
        "ARIA-128",
        "ARIA-192",
        "ARIA-256",
        "CAMELLIA-128",
        "CAMELLIA-192",
        "CAMELLIA-256",
        "SEED",
        "SM4",
    }
)


_OPENVPN_CANONICAL_DATA_CIPHERS = frozenset(
    {
        f"{base}-{mode}"
        for base in _OPENVPN_STREAM_CIPHER_BASES
        for mode in ("CBC", "CFB", "OFB")
    }
    | {
        "AES-128-GCM",
        "AES-192-GCM",
        "AES-256-GCM",
        "CHACHA20-POLY1305",
        "NONE",
    }
)


def _is_valid_openvpn_server(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(char.isspace() for char in value)
        and "[" not in value
        and "]" not in value
    )


def _openvpn_tls(data: dict[str, Any]) -> tuple[str, str | None, str | None]:
    value = data.get("tls")
    if not isinstance(value, dict):
        raise SingBoxCodecError(
            "tls",
            "Sing-box OpenVPN client requires an inline TLS object",
            "parse.singbox.unsupported-protocol-variant",
        )
    unknown = sorted(set(value) - _OPENVPN_TLS_KEYS)
    if unknown:
        field = f"tls.{unknown[0]}"
        raise SingBoxCodecError(
            field,
            f"Sing-box OpenVPN TLS field '{unknown[0]}' is not supported",
            unsupported_field_code(field),
        )
    try:
        certificate = _optional_string(value, "certificate")
        client_certificate = _optional_string(value, "client_certificate") or None
        client_key = _optional_string(value, "client_key") or None
    except SingBoxCodecError as exc:
        raise SingBoxCodecError(f"tls.{exc.field}", str(exc), exc.code) from exc
    if not certificate:
        raise SingBoxCodecError(
            "tls.certificate",
            "Sing-box OpenVPN client requires an inline CA certificate",
            "parse.singbox.unsupported-protocol-variant",
        )
    return certificate, client_certificate, client_key


class SingBoxOpenVPNClientEndpointCodec(SingBoxEndpointCodec):
    singbox_type = "openvpn-client"
    protocol = Protocol.OPENVPN
    node_class = OpenVPNNode
    allowed_keys = _OPENVPN_KEYS
    allowed_node_fields = _COMMON_NODE_FIELDS | frozenset(
        {
            "server",
            "port",
            "proto",
            "dev",
            "cipher",
            "data_ciphers",
            "data_ciphers_fallback",
            "auth",
            "comp_lzo",
            "ca",
            "certificate",
            "private_key",
            "username",
            "password",
            "mtu",
        }
    )
    expected_udp = True

    def parse(self, data: dict[str, Any]) -> OpenVPNNode:
        mode = _optional_enum_string(data, "mode", frozenset({"tls", "static_key"}))
        if mode not in {None, "tls"}:
            raise SingBoxCodecError(
                "mode",
                "Sing-box OpenVPN static-key mode is not supported",
                "parse.singbox.unsupported-protocol-variant",
            )
        network = _optional_enum_string(data, "network", _OPENVPN_NETWORKS) or "udp"
        if network not in _OPENVPN_NETWORK_TO_PROTO:
            raise SingBoxCodecError(
                "network",
                f"Sing-box OpenVPN network '{network}' cannot be represented",
                "parse.singbox.unsupported-protocol-variant",
            )
        port = _optional_int(data, "server_port")
        if port is None or not 1 <= port <= 65535:
            raise SingBoxCodecError(
                "server_port",
                "Sing-box OpenVPN server_port must be between 1 and 65535",
                "parse.singbox.invalid-field",
            )
        mtu = _optional_int(data, "mtu")
        if mtu is not None and not 0 <= mtu <= _ROUTING_MARK_MAX:
            raise SingBoxCodecError(
                "mtu",
                f"Sing-box OpenVPN mtu must be between 0 and {_ROUTING_MARK_MAX}",
                "parse.singbox.invalid-field",
            )
        ca, certificate, private_key = _openvpn_tls(data)
        server = _required_string(data, "server")
        if not _is_valid_openvpn_server(server):
            raise SingBoxCodecError(
                "server",
                "Sing-box OpenVPN server must be a non-empty host without whitespace",
                "parse.singbox.invalid-field",
            )
        data_ciphers = _string_or_list(data, "data_ciphers")
        if data_ciphers is not None and any(
            value not in _OPENVPN_CANONICAL_DATA_CIPHERS for value in data_ciphers
        ):
            raise SingBoxCodecError(
                "data_ciphers",
                "Sing-box OpenVPN data_ciphers must use canonical cipher names",
                "parse.singbox.invalid-field",
            )
        data_ciphers_fallback = _optional_string(data, "data_ciphers_fallback") or None
        if (
            data_ciphers_fallback is not None
            and data_ciphers_fallback not in _OPENVPN_CANONICAL_DATA_CIPHERS
        ):
            raise SingBoxCodecError(
                "data_ciphers_fallback",
                "Sing-box OpenVPN data_ciphers_fallback must use a canonical cipher name",
                "parse.singbox.invalid-field",
            )
        kwargs = _common_kwargs(data, udp=True)
        kwargs.update(
            server=server,
            port=port,
            proto=_OPENVPN_NETWORK_TO_PROTO[network],
            data_ciphers=data_ciphers,
            data_ciphers_fallback=data_ciphers_fallback,
            auth=_optional_string(data, "auth") or "SHA256",
            comp_lzo=_optional_enum_string(
                data, "compression_lzo", _OPENVPN_COMPRESSION_LZO
            )
            or "no",
            ca=ca,
            certificate=certificate,
            private_key=private_key,
            username=_optional_string(data, "username"),
            password=_optional_string(data, "password"),
            mtu=1500 if mtu is None else mtu,
        )
        return OpenVPNNode(**kwargs)

    def _check_protocol(self, node: Node) -> list[str]:
        assert isinstance(node, OpenVPNNode)
        unsupported = []
        if not _is_valid_openvpn_server(node.server):
            unsupported.append("server")
        if type(node.port) is not int or not 1 <= node.port <= 65535:
            unsupported.append("port")
        if (
            not isinstance(node.proto, str)
            or node.proto not in _OPENVPN_PROTO_TO_NETWORK
        ):
            unsupported.append("proto")
        if node.dev != "tun":
            unsupported.append("dev")
        if node.cipher != "AES-128-GCM":
            unsupported.append("cipher")
        if not isinstance(node.auth, str) or node.auth not in _OPENVPN_AUTH_METHODS:
            unsupported.append("auth")
        if (
            not isinstance(node.comp_lzo, str)
            or node.comp_lzo not in _OPENVPN_COMPRESSION_LZO
        ):
            unsupported.append("comp_lzo")
        if not isinstance(node.ca, str) or not node.ca:
            unsupported.append("ca")
        if node.data_ciphers is not None and (
            not isinstance(node.data_ciphers, list)
            or not all(
                isinstance(value, str) and value in _OPENVPN_CANONICAL_DATA_CIPHERS
                for value in node.data_ciphers
            )
        ):
            unsupported.append("data_ciphers")
        if node.data_ciphers_fallback is not None and (
            not isinstance(node.data_ciphers_fallback, str)
            or node.data_ciphers_fallback not in _OPENVPN_CANONICAL_DATA_CIPHERS
        ):
            unsupported.append("data_ciphers_fallback")
        for field in ("certificate", "private_key", "username", "password"):
            value = getattr(node, field)
            if value is not None and (
                not isinstance(value, str)
                or (field in {"certificate", "private_key"} and not value)
            ):
                unsupported.append(field)
        if bool(node.certificate) != bool(node.private_key):
            unsupported.extend(("certificate", "private_key"))
        if type(node.mtu) is not int or not 0 <= node.mtu <= _ROUTING_MARK_MAX:
            unsupported.append("mtu")
        return unsupported

    def _emit_protocol(self, out: dict[str, Any], node: Node) -> None:
        assert isinstance(node, OpenVPNNode)
        out.update(
            server=node.server,
            server_port=node.port,
            mode="tls",
            network=_OPENVPN_PROTO_TO_NETWORK[node.proto],
            auth=node.auth,
            compression_lzo=node.comp_lzo,
            mtu=node.mtu,
        )
        if node.username is not None:
            out["username"] = node.username
        if node.password is not None:
            out["password"] = node.password
        if node.data_ciphers is not None:
            out["data_ciphers"] = list(node.data_ciphers)
        if node.data_ciphers_fallback is not None:
            out["data_ciphers_fallback"] = node.data_ciphers_fallback
        tls = {"certificate": node.ca}
        if node.certificate is not None:
            tls["client_certificate"] = node.certificate
        if node.private_key is not None:
            tls["client_key"] = node.private_key
        out["tls"] = tls


CODEC = SingBoxOpenVPNClientEndpointCodec()
