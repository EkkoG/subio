from __future__ import annotations

from dataclasses import fields
from typing import Any

from subio_v2.core.nodes import (
    AnyTLSNode,
    BaseNode,
    DirectNode,
    HttpNode,
    Hysteria2Node,
    HysteriaNode,
    NaiveNode,
    Node,
    Protocol,
    RejectMode,
    RejectNode,
    ShadowsocksNode,
    ShadowTLSNode,
    SnellNode,
    Socks5Node,
    SSHNode,
    TLSSettings,
    TrojanNode,
    TUICNode,
    VlessNode,
    VmessNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


class SingBoxCodecError(ValueError):
    def __init__(self, field: str, message: str, code: str):
        super().__init__(message)
        self.field = field
        self.code = code


_COMMON_KEYS = frozenset(
    {
        "type",
        "tag",
        "detour",
        "bind_interface",
        "routing_mark",
        "tcp_fast_open",
        "tcp_multi_path",
    }
)
_ENDPOINT_KEYS = frozenset({"server", "server_port"})
_UNSAFE_FIELDS = frozenset(
    {
        "protect_path",
        "netns",
        "certificate_path",
        "client_certificate_path",
        "client_key_path",
        "private_key_path",
        "state_dir",
        "state_directory",
        "taildrop_directory",
        "interactive_login",
    }
)
_TLS_KEYS = frozenset({"enabled", "disable_sni", "server_name", "insecure", "alpn"})
_ROUTING_MARK_MAX = 4_294_967_295
_SHADOWSOCKS_METHODS = frozenset(
    {
        "none",
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "rc4-md5",
        "chacha20-ietf",
        "xchacha20",
    }
)
_VMESS_SECURITY_VALUES = frozenset(
    {"auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"}
)
_VMESS_PACKET_ENCODINGS = frozenset({"packetaddr", "xudp"})
_SNELL_V4_OBFS_MODES = frozenset({"none", "http", "tls"})
_SNELL_V6_MODES = frozenset({"default", "unshaped", "unsafe-raw"})
_COMMON_NODE_FIELDS = frozenset(
    {
        "name",
        "type",
        "server",
        "port",
        "udp",
        "tfo",
        "mptcp",
        "dialer_proxy",
        "interface_name",
        "routing_mark",
        "record",
    }
)
_MINIMAL_NODE_FIELDS = frozenset({"name", "type", "record"})


def unsupported_field_code(field: str) -> str:
    leaf = field.rsplit(".", 1)[-1]
    if leaf in _UNSAFE_FIELDS or (leaf.endswith("_path") and leaf != "tcp_multi_path"):
        return "parse.singbox.unsafe-field"
    return "parse.singbox.unsupported-field"


def _optional_string(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise SingBoxCodecError(
            key,
            f"Sing-box field '{key}' must be a string",
            "parse.singbox.invalid-field",
        )
    return value


def _optional_bool(data: dict[str, Any], key: str, default: bool = False) -> bool:
    value = data.get(key, default)
    if type(value) is not bool:
        raise SingBoxCodecError(
            key,
            f"Sing-box field '{key}' must be a boolean",
            "parse.singbox.invalid-field",
        )
    return value


def _optional_int(data: dict[str, Any], key: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if type(value) is not int:
        raise SingBoxCodecError(
            key,
            f"Sing-box field '{key}' must be an integer",
            "parse.singbox.invalid-field",
        )
    return value


def _optional_enum_string(
    data: dict[str, Any], key: str, allowed: frozenset[str]
) -> str | None:
    value = _optional_string(data, key)
    if value is not None and value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise SingBoxCodecError(
            key,
            f"Sing-box field '{key}' must be one of: {choices}",
            "parse.singbox.invalid-field",
        )
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise SingBoxCodecError(
        field,
        f"Sing-box field '{field}' must be a string or string array",
        "parse.singbox.invalid-field",
    )


def _parse_tls(value: Any, *, force_enabled: bool) -> TLSSettings:
    if value is None:
        return TLSSettings(enabled=force_enabled)
    if not isinstance(value, dict):
        raise SingBoxCodecError(
            "tls",
            "Sing-box field 'tls' must be an object",
            "parse.singbox.invalid-field",
        )
    unknown = sorted(set(value) - _TLS_KEYS)
    if unknown:
        field = f"tls.{unknown[0]}"
        raise SingBoxCodecError(
            field,
            f"Sing-box TLS field '{unknown[0]}' is not supported",
            unsupported_field_code(field),
        )
    alpn = None
    if "alpn" in value:
        alpn = _string_list(value["alpn"], "tls.alpn")
    return TLSSettings(
        enabled=_optional_bool(value, "enabled", force_enabled),
        sni_disabled=_optional_bool(value, "disable_sni"),
        server_name=_optional_string(value, "server_name"),
        skip_cert_verify=_optional_bool(value, "insecure"),
        alpn=alpn,
    )


def _emit_tls(tls: TLSSettings) -> dict[str, Any]:
    out: dict[str, Any] = {"enabled": tls.enabled}
    if tls.sni_disabled:
        out["disable_sni"] = True
    if tls.server_name:
        out["server_name"] = tls.server_name
    if tls.skip_cert_verify:
        out["insecure"] = True
    if tls.alpn:
        out["alpn"] = list(tls.alpn)
    return out


def _parse_network(data: dict[str, Any]) -> bool:
    value = data.get("network")
    if value is None:
        return True
    values = _string_list(value, "network")
    if values == ["tcp"]:
        return False
    if len(values) == 2 and set(values) == {"tcp", "udp"}:
        return True
    raise SingBoxCodecError(
        "network",
        "Sing-box network must be 'tcp' or contain both 'tcp' and 'udp'",
        "parse.singbox.unsupported-field",
    )


class SingBoxOutboundCodec:
    def __init__(
        self,
        singbox_type: str,
        protocol: Protocol,
        node_class: type[BaseNode],
        protocol_keys: frozenset[str],
        allowed_node_fields: frozenset[str],
        *,
        endpoint: bool = True,
        network: bool = False,
        tcp_only: bool = False,
        force_tls: bool = False,
        common_options: bool = True,
    ):
        self.singbox_type = singbox_type
        self.protocol = protocol
        self.node_class = node_class
        self.endpoint = endpoint
        self.network = network
        self.tcp_only = tcp_only
        self.force_tls = force_tls
        self.common_options = common_options
        base_keys = _COMMON_KEYS if common_options else frozenset({"type", "tag"})
        self.allowed_keys = base_keys | protocol_keys
        if endpoint:
            self.allowed_keys |= _ENDPOINT_KEYS
        base_node_fields = (
            _COMMON_NODE_FIELDS if common_options else _MINIMAL_NODE_FIELDS
        )
        self.allowed_node_fields = base_node_fields | allowed_node_fields

    @property
    def target_constraints(self) -> dict[str, object]:
        return {}

    def parse(self, data: dict[str, Any]) -> Node:
        tag = data.get("tag")
        if not isinstance(tag, str) or not tag:
            raise SingBoxCodecError(
                "tag",
                "Sing-box outbound field 'tag' must be a non-empty string",
                "parse.singbox.invalid-field",
            )
        routing_mark = data.get("routing_mark")
        if routing_mark is not None and type(routing_mark) is not int:
            raise SingBoxCodecError(
                "routing_mark",
                "String routing marks are not supported",
                "parse.singbox.unsupported-field",
            )
        if routing_mark is not None and not 0 <= routing_mark <= _ROUTING_MARK_MAX:
            raise SingBoxCodecError(
                "routing_mark",
                f"Sing-box field 'routing_mark' must be between 0 and {_ROUTING_MARK_MAX}",
                "parse.singbox.invalid-field",
            )
        kwargs: dict[str, Any] = {
            "name": tag,
            "type": self.protocol,
            "server": _optional_string(data, "server") if self.endpoint else None,
            "port": _optional_int(data, "server_port") if self.endpoint else None,
            "udp": False
            if self.tcp_only
            else (_parse_network(data) if self.network else True),
            "dialer_proxy": _optional_string(data, "detour"),
            "interface_name": _optional_string(data, "bind_interface"),
            "routing_mark": routing_mark,
            "tfo": _optional_bool(data, "tcp_fast_open"),
            "mptcp": _optional_bool(data, "tcp_multi_path"),
        }
        kwargs.update(self._parse_protocol_fields(data))
        return self.node_class(**kwargs)

    def _parse_protocol_fields(self, data: dict[str, Any]) -> dict[str, Any]:
        protocol = self.protocol
        if protocol == Protocol.ANYTLS:
            return {
                "password": _optional_string(data, "password") or "",
                "tls": _parse_tls(data.get("tls"), force_enabled=True),
            }
        if protocol == Protocol.REJECT:
            return {"mode": RejectMode.REJECT}
        if protocol == Protocol.DIRECT:
            return {}
        if protocol == Protocol.HTTP:
            return {
                "username": _optional_string(data, "username"),
                "password": _optional_string(data, "password"),
                "tls": _parse_tls(data.get("tls"), force_enabled=False),
            }
        if protocol == Protocol.HYSTERIA:
            return {
                "auth": _optional_string(data, "auth"),
                "auth_str": _optional_string(data, "auth_str"),
                "obfs": _optional_string(data, "obfs"),
                "tls": _parse_tls(data.get("tls"), force_enabled=True),
            }
        if protocol == Protocol.HYSTERIA2:
            return {
                "password": _optional_string(data, "password") or "",
                "tls": _parse_tls(data.get("tls"), force_enabled=True),
            }
        if protocol == Protocol.NAIVE:
            return {
                "username": _optional_string(data, "username"),
                "password": _optional_string(data, "password"),
                "tls": _parse_tls(data.get("tls"), force_enabled=True),
            }
        if protocol == Protocol.SHADOWSOCKS:
            return {
                "cipher": _optional_enum_string(data, "method", _SHADOWSOCKS_METHODS)
                or "",
                "password": _optional_string(data, "password") or "",
            }
        if protocol == Protocol.SHADOWTLS:
            version = _optional_int(data, "version") or 1
            if version not in {1, 2, 3}:
                raise SingBoxCodecError(
                    "version",
                    "ShadowTLS version must be 1, 2, or 3",
                    "parse.singbox.invalid-field",
                )
            password = _optional_string(data, "password")
            if version == 1 and password:
                raise SingBoxCodecError(
                    "password",
                    "ShadowTLS v1 does not support a password",
                    "parse.singbox.unsupported-protocol-variant",
                )
            if "tls" not in data:
                raise SingBoxCodecError(
                    "tls",
                    "ShadowTLS requires an enabled TLS object",
                    "parse.singbox.invalid-field",
                )
            tls = _parse_tls(data["tls"], force_enabled=True)
            if not tls.enabled:
                raise SingBoxCodecError(
                    "tls.enabled",
                    "ShadowTLS requires TLS to be enabled",
                    "parse.singbox.unsupported-protocol-variant",
                )
            return {
                "version": version,
                "password": password,
                "tls": tls,
            }
        if protocol == Protocol.SNELL:
            version = _optional_int(data, "version")
            if version not in {4, 6}:
                raise SingBoxCodecError(
                    "version",
                    "Sing-box Snell version must be 4 or 6",
                    "parse.singbox.unsupported-protocol-variant",
                )
            out = {
                "psk": _optional_string(data, "psk") or "",
                "version": version,
                "reuse": data.get("reuse"),
            }
            if "reuse" in data and type(data["reuse"]) is not bool:
                raise SingBoxCodecError(
                    "reuse",
                    "Sing-box field 'reuse' must be a boolean",
                    "parse.singbox.invalid-field",
                )
            if version == 4:
                if "mode" in data:
                    raise SingBoxCodecError(
                        "mode",
                        "Sing-box Snell v4 does not support mode",
                        "parse.singbox.unsupported-protocol-variant",
                    )
                out["obfs"] = _optional_enum_string(
                    data, "obfs_mode", _SNELL_V4_OBFS_MODES
                )
                out["obfs_host"] = _optional_string(data, "obfs_host")
            else:
                for field in ("obfs_mode", "obfs_host"):
                    if field in data:
                        raise SingBoxCodecError(
                            field,
                            f"Sing-box Snell v6 does not support {field}",
                            "parse.singbox.unsupported-protocol-variant",
                        )
                out["mode"] = _optional_enum_string(data, "mode", _SNELL_V6_MODES)
            return out
        if protocol == Protocol.SOCKS5:
            version = _optional_string(data, "version") or "5"
            if version != "5":
                raise SingBoxCodecError(
                    "version",
                    "Only SOCKS5 can be represented by the SubIO SOCKS node",
                    "parse.singbox.unsupported-protocol-variant",
                )
            return {
                "username": _optional_string(data, "username"),
                "password": _optional_string(data, "password"),
            }
        if protocol == Protocol.SSH:
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
                algorithms = _string_list(
                    data["host_key_algorithms"], "host_key_algorithms"
                )
            return {
                "username": _optional_string(data, "user") or "",
                "password": _optional_string(data, "password"),
                "private_key": private_key,
                "private_key_passphrase": _optional_string(
                    data, "private_key_passphrase"
                ),
                "host_key": host_key,
                "host_key_algorithms": algorithms,
            }
        if protocol == Protocol.TROJAN:
            return {
                "password": _optional_string(data, "password") or "",
                "tls": _parse_tls(data.get("tls"), force_enabled=False),
            }
        if protocol == Protocol.TUIC:
            return {
                "uuid": _optional_string(data, "uuid"),
                "password": _optional_string(data, "password"),
                "version": 5,
                "tls": _parse_tls(data.get("tls"), force_enabled=True),
            }
        if protocol == Protocol.VLESS:
            return {
                "uuid": _optional_string(data, "uuid") or "",
                "flow": _optional_string(data, "flow"),
                "packet_encoding": _optional_string(data, "packet_encoding"),
                "tls": _parse_tls(data.get("tls"), force_enabled=False),
            }
        if protocol == Protocol.VMESS:
            return {
                "uuid": _optional_string(data, "uuid") or "",
                "cipher": _optional_enum_string(
                    data, "security", _VMESS_SECURITY_VALUES
                )
                or "auto",
                "alter_id": _optional_int(data, "alter_id") or 0,
                "global_padding": _optional_bool(data, "global_padding"),
                "packet_encoding": _optional_enum_string(
                    data, "packet_encoding", _VMESS_PACKET_ENCODINGS
                ),
                "tls": _parse_tls(data.get("tls"), force_enabled=False),
            }
        raise TypeError(f"No sing-box parser for {protocol.value}")

    def check(self, node: Node) -> list[IssueDraft]:
        if not isinstance(node, self.node_class):
            return [
                IssueDraft(
                    IssueSeverity.ERROR,
                    f"Expected {self.node_class.__name__}, got {type(node).__name__}",
                    "type",
                )
            ]
        default = self.node_class(name="__singbox_default__")
        unsupported = []
        for item in fields(node):
            if item.name in self.allowed_node_fields:
                continue
            if getattr(node, item.name) != getattr(default, item.name):
                unsupported.append(item.name)
        if self.tcp_only and node.udp:
            unsupported.append("udp")
        tls = getattr(node, "tls", None)
        if isinstance(tls, TLSSettings):
            advanced_tls = (
                "client_fingerprint",
                "reality_opts",
                "ech_opts",
                "certificate",
                "private_key",
                "verify_name",
                "certificate_sha256",
                "client_cert_ref",
            )
            unsupported.extend(
                f"tls.{name}" for name in advanced_tls if getattr(tls, name)
            )
            if self.force_tls and not tls.enabled:
                unsupported.append("tls.enabled")
        if isinstance(node, RejectNode) and node.mode != RejectMode.REJECT:
            unsupported.append("mode")
        if self.common_options and node.routing_mark is not None:
            if type(node.routing_mark) is not int or not (
                0 <= node.routing_mark <= _ROUTING_MARK_MAX
            ):
                unsupported.append("routing_mark")
        if (
            isinstance(node, ShadowsocksNode)
            and node.cipher not in _SHADOWSOCKS_METHODS
        ):
            unsupported.append("cipher")
        if isinstance(node, SnellNode):
            if node.version not in {4, 6}:
                unsupported.append("version")
            elif node.version == 4 and node.obfs not in {None, *_SNELL_V4_OBFS_MODES}:
                unsupported.append("obfs")
            elif node.version == 4 and node.mode is not None:
                unsupported.append("mode")
            elif node.version == 6:
                if node.mode not in {None, *_SNELL_V6_MODES}:
                    unsupported.append("mode")
                if node.obfs is not None:
                    unsupported.append("obfs")
                if node.obfs_host is not None:
                    unsupported.append("obfs_host")
        if isinstance(node, ShadowTLSNode):
            if node.version not in {1, 2, 3}:
                unsupported.append("version")
            if node.version == 1 and node.password:
                unsupported.append("password")
        if isinstance(node, TUICNode) and (node.version not in {None, 5} or node.token):
            unsupported.append("version")
        if isinstance(node, VmessNode):
            if node.cipher not in _VMESS_SECURITY_VALUES:
                unsupported.append("cipher")
            if (
                node.packet_encoding is not None
                and node.packet_encoding not in _VMESS_PACKET_ENCODINGS
            ):
                unsupported.append("packet_encoding")
        return [
            IssueDraft(
                IssueSeverity.ERROR,
                f"Node field cannot be represented by sing-box: {field}",
                field,
                code="conversion.unsupported-platform-field",
            )
            for field in sorted(set(unsupported))
        ]

    def encode(self, node: Node) -> dict[str, Any]:
        issues = self.check(node)
        if issues:
            issue = issues[0]
            raise SingBoxCodecError(issue.field or "node", issue.message, issue.code)
        out: dict[str, Any] = {"type": self.singbox_type, "tag": node.name}
        if self.endpoint:
            out["server"] = node.server
            out["server_port"] = node.port
        if self.common_options:
            if node.dialer_proxy:
                out["detour"] = node.dialer_proxy
            if node.interface_name:
                out["bind_interface"] = node.interface_name
            if node.routing_mark is not None:
                out["routing_mark"] = node.routing_mark
            if node.tfo:
                out["tcp_fast_open"] = True
            if node.mptcp:
                out["tcp_multi_path"] = True
        if self.network and not node.udp:
            out["network"] = "tcp"
        self._emit_protocol_fields(out, node)
        return out

    def _emit_protocol_fields(self, out: dict[str, Any], node: Node) -> None:
        if isinstance(node, AnyTLSNode):
            out["password"] = node.password
            out["tls"] = _emit_tls(node.tls)
        elif isinstance(node, (RejectNode, DirectNode)):
            return
        elif isinstance(node, HttpNode):
            if node.username:
                out["username"] = node.username
            if node.password:
                out["password"] = node.password
            if node.tls.enabled or node.tls.server_name or node.tls.alpn:
                out["tls"] = _emit_tls(node.tls)
        elif isinstance(node, HysteriaNode):
            if node.auth:
                out["auth"] = node.auth
            if node.auth_str:
                out["auth_str"] = node.auth_str
            if node.obfs:
                out["obfs"] = node.obfs
            out["tls"] = _emit_tls(node.tls)
        elif isinstance(node, Hysteria2Node):
            out["password"] = node.password
            out["tls"] = _emit_tls(node.tls)
        elif isinstance(node, NaiveNode):
            if node.username:
                out["username"] = node.username
            if node.password:
                out["password"] = node.password
            out["tls"] = _emit_tls(node.tls)
        elif isinstance(node, ShadowsocksNode):
            out["method"] = node.cipher
            out["password"] = node.password
        elif isinstance(node, ShadowTLSNode):
            out["version"] = node.version
            if node.password:
                out["password"] = node.password
            out["tls"] = _emit_tls(node.tls)
        elif isinstance(node, SnellNode):
            out["version"] = node.version
            out["psk"] = node.psk
            if node.reuse is not None:
                out["reuse"] = node.reuse
            if node.version == 4:
                if node.obfs:
                    out["obfs_mode"] = node.obfs
                if node.obfs_host:
                    out["obfs_host"] = node.obfs_host
            elif node.mode:
                out["mode"] = node.mode
        elif isinstance(node, Socks5Node):
            out["version"] = "5"
            if node.username:
                out["username"] = node.username
            if node.password:
                out["password"] = node.password
        elif isinstance(node, SSHNode):
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
        elif isinstance(node, TrojanNode):
            out["password"] = node.password
            if node.tls.enabled or node.tls.server_name or node.tls.alpn:
                out["tls"] = _emit_tls(node.tls)
        elif isinstance(node, TUICNode):
            out["uuid"] = node.uuid
            out["password"] = node.password
            out["tls"] = _emit_tls(node.tls)
        elif isinstance(node, VlessNode):
            out["uuid"] = node.uuid
            if node.flow:
                out["flow"] = node.flow
            if node.packet_encoding:
                out["packet_encoding"] = node.packet_encoding
            if node.tls.enabled or node.tls.server_name or node.tls.alpn:
                out["tls"] = _emit_tls(node.tls)
        elif isinstance(node, VmessNode):
            out["uuid"] = node.uuid
            out["security"] = node.cipher
            if node.alter_id:
                out["alter_id"] = node.alter_id
            if node.global_padding:
                out["global_padding"] = True
            if node.packet_encoding:
                out["packet_encoding"] = node.packet_encoding
            if node.tls.enabled or node.tls.server_name or node.tls.alpn:
                out["tls"] = _emit_tls(node.tls)


def _keys(*values: str) -> frozenset[str]:
    return frozenset(values)


_CODECS = (
    SingBoxOutboundCodec(
        "anytls",
        Protocol.ANYTLS,
        AnyTLSNode,
        _keys("password", "tls"),
        _keys("password", "tls"),
        tcp_only=True,
        force_tls=True,
    ),
    SingBoxOutboundCodec(
        "block",
        Protocol.REJECT,
        RejectNode,
        frozenset(),
        _keys("mode", "udp"),
        endpoint=False,
        tcp_only=True,
        common_options=False,
    ),
    SingBoxOutboundCodec(
        "direct", Protocol.DIRECT, DirectNode, frozenset(), frozenset(), endpoint=False
    ),
    SingBoxOutboundCodec(
        "http",
        Protocol.HTTP,
        HttpNode,
        _keys("username", "password", "tls"),
        _keys("username", "password", "tls"),
        tcp_only=True,
    ),
    SingBoxOutboundCodec(
        "hysteria",
        Protocol.HYSTERIA,
        HysteriaNode,
        _keys("auth", "auth_str", "obfs", "tls"),
        _keys("auth", "auth_str", "obfs", "tls"),
        force_tls=True,
    ),
    SingBoxOutboundCodec(
        "hysteria2",
        Protocol.HYSTERIA2,
        Hysteria2Node,
        _keys("password", "tls"),
        _keys("password", "tls"),
        force_tls=True,
    ),
    SingBoxOutboundCodec(
        "naive",
        Protocol.NAIVE,
        NaiveNode,
        _keys("username", "password", "tls"),
        _keys("username", "password", "tls"),
        tcp_only=True,
        force_tls=True,
    ),
    SingBoxOutboundCodec(
        "shadowsocks",
        Protocol.SHADOWSOCKS,
        ShadowsocksNode,
        _keys("method", "password", "network"),
        _keys("cipher", "password"),
        network=True,
    ),
    SingBoxOutboundCodec(
        "shadowtls",
        Protocol.SHADOWTLS,
        ShadowTLSNode,
        _keys("version", "password", "tls"),
        _keys("version", "password", "tls"),
        tcp_only=True,
        force_tls=True,
    ),
    SingBoxOutboundCodec(
        "snell",
        Protocol.SNELL,
        SnellNode,
        _keys("version", "psk", "reuse", "network", "obfs_mode", "obfs_host", "mode"),
        _keys("psk", "version", "reuse", "mode", "obfs", "obfs_host"),
        network=True,
    ),
    SingBoxOutboundCodec(
        "socks",
        Protocol.SOCKS5,
        Socks5Node,
        _keys("version", "username", "password", "network"),
        _keys("username", "password"),
        network=True,
    ),
    SingBoxOutboundCodec(
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
        tcp_only=True,
    ),
    SingBoxOutboundCodec(
        "trojan",
        Protocol.TROJAN,
        TrojanNode,
        _keys("password", "network", "tls"),
        _keys("password", "tls"),
        network=True,
    ),
    SingBoxOutboundCodec(
        "tuic",
        Protocol.TUIC,
        TUICNode,
        _keys("uuid", "password", "network", "tls"),
        _keys("uuid", "password", "version", "tls"),
        network=True,
        force_tls=True,
    ),
    SingBoxOutboundCodec(
        "vless",
        Protocol.VLESS,
        VlessNode,
        _keys("uuid", "flow", "network", "tls", "packet_encoding"),
        _keys("uuid", "flow", "tls", "packet_encoding"),
        network=True,
    ),
    SingBoxOutboundCodec(
        "vmess",
        Protocol.VMESS,
        VmessNode,
        _keys(
            "uuid",
            "security",
            "alter_id",
            "global_padding",
            "network",
            "tls",
            "packet_encoding",
        ),
        _keys("uuid", "alter_id", "cipher", "global_padding", "tls", "packet_encoding"),
        network=True,
    ),
)

SINGBOX_OUTBOUND_CODECS = {codec.protocol: codec for codec in _CODECS}
SINGBOX_OUTBOUND_CODECS_BY_TYPE = {codec.singbox_type: codec for codec in _CODECS}


def encode_outbound(node: Node) -> dict[str, Any]:
    codec = SINGBOX_OUTBOUND_CODECS.get(node.type)
    if codec is None:
        raise SingBoxCodecError(
            "type",
            f"Protocol '{node.type.value}' is not supported by sing-box",
            "conversion.unsupported-protocol",
        )
    return codec.encode(node)
