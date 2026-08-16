from __future__ import annotations

import argparse
import json
import types
from dataclasses import fields
from enum import StrEnum
from pathlib import Path
from typing import Any, Union, get_args, get_origin, get_type_hints

from subio_v2.model.nodes import (
    Protocol,
    ShadowTLSSettings,
    SmuxSettings,
    SudokuHTTPMaskSettings,
    SurgePolicyOptions,
    TLSSettings,
    TransportSettings,
    WireguardPeer,
)

SUBIO_FORMAT_VERSION = 1

NON_PUBLIC_NODE_FIELDS = frozenset(
    {
        "original_name",
        "extra",
        "source_extensions",
        "source_provider",
        "source_context",
    }
)

PUBLIC_COMMON_FIELDS = frozenset(
    {
        "name",
        "type",
        "server",
        "port",
        "udp",
        "ip_version",
        "tfo",
        "mptcp",
        "dialer_proxy",
        "users",
        "interface_name",
        "routing_mark",
        "surge_options",
        "shadow_tls",
    }
)

PUBLIC_PROTOCOL_FIELDS: dict[Protocol, frozenset[str]] = {
    Protocol.SHADOWSOCKS: frozenset(
        {"cipher", "password", "udp_port", "plugin", "plugin_opts", "smux"}
    ),
    Protocol.SHADOWSOCKSR: frozenset(
        {
            "cipher",
            "password",
            "obfs",
            "ssr_protocol",
            "obfs_param",
            "protocol_param",
            "smux",
        }
    ),
    Protocol.VMESS: frozenset(
        {
            "uuid",
            "alter_id",
            "cipher",
            "global_padding",
            "vmess_aead",
            "tls",
            "transport",
            "smux",
            "packet_encoding",
        }
    ),
    Protocol.VLESS: frozenset(
        {"uuid", "flow", "tls", "transport", "smux", "packet_encoding"}
    ),
    Protocol.TROJAN: frozenset({"password", "tls", "transport", "smux"}),
    Protocol.SOCKS5: frozenset({"username", "password", "tls"}),
    Protocol.HTTP: frozenset(
        {"username", "password", "headers", "variant", "max_streams", "tls"}
    ),
    Protocol.WIREGUARD: frozenset(
        {
            "private_key",
            "public_key",
            "preshared_key",
            "interface_ip",
            "interface_ipv6",
            "allowed_ips",
            "reserved",
            "mtu",
            "workers",
            "persistent_keepalive",
            "amnezia_wg_option",
            "peers",
            "remote_dns_resolve",
            "dns_servers",
            "refresh_server_ip_interval",
            "smux",
        }
    ),
    Protocol.TAILSCALE: frozenset(
        {
            "hostname",
            "auth_key",
            "interactive_login",
            "control_url",
            "state_dir",
            "ephemeral",
            "accept_routes",
            "exit_node",
            "exit_node_auto_fallback",
            "exit_node_allow_lan_access",
            "derp_only",
            "auto_add_magic_dns_rule",
            "idle_keepalive",
            "prefer_ipv6",
            "dns_servers",
            "mtu",
            "smux",
        }
    ),
    Protocol.MASQUE: frozenset(
        {
            "mode",
            "transport",
            "connect_uri",
            "username",
            "password",
            "private_key",
            "public_key",
            "interface_ip",
            "interface_ipv6",
            "mtu",
            "ports",
            "hop_interval",
            "remote_dns_resolve",
            "dns_servers",
            "congestion_controller",
            "cwnd",
            "bbr_profile",
            "handshake_timeout",
            "tls",
            "smux",
        }
    ),
    Protocol.TRUSTTUNNEL: frozenset(
        {
            "username",
            "password",
            "headers",
            "max_streams",
            "quic",
            "websocket",
            "health_check",
            "congestion_controller",
            "cwnd",
            "bbr_profile",
            "max_connections",
            "min_streams",
            "tls",
            "smux",
        }
    ),
    Protocol.DIRECT: frozenset({"smux"}),
    Protocol.DNS: frozenset({"smux"}),
    Protocol.REMATCH: frozenset(
        {"target_rematch_name", "target_sub_rule", "smux"}
    ),
    Protocol.GOST_RELAY: frozenset(
        {"forward", "mux", "username", "password", "tls", "smux"}
    ),
    Protocol.SHADOWQUIC: frozenset(
        {
            "username",
            "password",
            "tls",
            "quic_versions",
            "udp_over_stream",
            "zero_rtt",
            "keep_alive_interval",
            "congestion_controller",
            "up",
            "down",
            "cwnd",
            "bbr_profile",
            "recv_window_conn",
            "recv_window",
            "disable_mtu_discovery",
            "max_datagram_frame_size",
            "max_open_streams",
            "smux",
        }
    ),
    Protocol.OPENVPN: frozenset(
        {
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
            "tls_auth",
            "key_direction",
            "tls_crypt",
            "tls_crypt_v2",
            "username",
            "password",
            "peer_info",
            "ping",
            "ping_restart",
            "handshake_timeout",
            "mtu",
            "remote_dns_resolve",
            "dns_servers",
            "smux",
        }
    ),
    Protocol.SUDOKU: frozenset(
        {
            "key",
            "aead_method",
            "padding_min",
            "padding_max",
            "table_type",
            "enable_pure_downlink",
            "multiplex",
            "httpmask",
            "custom_table",
            "custom_tables",
            "legacy_http_mask",
            "legacy_http_mask_mode",
            "legacy_http_mask_tls",
            "legacy_http_mask_host",
            "legacy_path_root",
            "legacy_http_mask_strategy",
            "legacy_http_mask_multiplex",
            "smux",
        }
    ),
    Protocol.REJECT: frozenset({"mode", "smux"}),
    Protocol.ANYTLS: frozenset(
        {
            "password",
            "tls",
            "reuse",
            "idle_session_check_interval",
            "idle_session_timeout",
            "min_idle_session",
        }
    ),
    Protocol.HYSTERIA: frozenset(
        {
            "ports",
            "hysteria_protocol",
            "obfs_protocol",
            "up",
            "down",
            "up_speed",
            "down_speed",
            "auth_str",
            "auth",
            "obfs",
            "hop_interval",
            "tls",
            "smux",
        }
    ),
    Protocol.HYSTERIA2: frozenset(
        {
            "password",
            "ports",
            "hop_interval",
            "up",
            "down",
            "obfs",
            "obfs_password",
            "tls",
            "smux",
        }
    ),
    Protocol.SSH: frozenset(
        {
            "username",
            "password",
            "private_key",
            "private_key_passphrase",
            "keystore_id",
            "host_key",
            "host_key_algorithms",
            "idle_timeout",
            "server_fingerprints",
        }
    ),
    Protocol.SNELL: frozenset(
        {
            "psk",
            "version",
            "reuse",
            "udp_port",
            "mode",
            "obfs",
            "obfs_host",
            "obfs_opts",
            "tls",
            "smux",
        }
    ),
    Protocol.MIERU: frozenset(
        {
            "port_range",
            "transport",
            "username",
            "password",
            "multiplexing",
            "handshake_mode",
            "traffic_pattern",
            "smux",
        }
    ),
    Protocol.JUICITY: frozenset({"uuid", "password", "tls"}),
    Protocol.TUIC: frozenset(
        {"token", "password", "uuid", "version", "ports", "hop_interval", "tls", "smux"}
    ),
}

PUBLIC_NESTED_FIELDS: dict[type, frozenset[str]] = {
    TLSSettings: frozenset(field.name for field in fields(TLSSettings)),
    ShadowTLSSettings: frozenset(field.name for field in fields(ShadowTLSSettings)),
    SurgePolicyOptions: frozenset(field.name for field in fields(SurgePolicyOptions)),
    SmuxSettings: frozenset(
        field.name for field in fields(SmuxSettings) if field.name != "extra"
    ),
    TransportSettings: frozenset(
        field.name for field in fields(TransportSettings) if field.name != "extra"
    ),
    SudokuHTTPMaskSettings: frozenset(
        field.name for field in fields(SudokuHTTPMaskSettings)
    ),
    WireguardPeer: frozenset(field.name for field in fields(WireguardPeer)),
}

PUBLIC_PROTOCOLS = frozenset(PUBLIC_PROTOCOL_FIELDS)


def public_node_fields(protocol: Protocol) -> frozenset[str]:
    return PUBLIC_COMMON_FIELDS | PUBLIC_PROTOCOL_FIELDS[protocol]


def build_json_schema() -> dict[str, Any]:
    import subio_v2.protocols as protocol_registry

    definitions: dict[str, Any] = {
        "jsonValue": {
            "anyOf": [
                {"type": "string"},
                {"type": "integer"},
                {"type": "number"},
                {"type": "boolean"},
                {"type": "array", "items": {"$ref": "#/$defs/jsonValue"}},
                {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/$defs/jsonValue"},
                },
            ]
        }
    }
    for cls, allowed_fields in PUBLIC_NESTED_FIELDS.items():
        hints = get_type_hints(cls)
        definitions[cls.__name__] = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                name: _json_schema_for_type(hints[name])
                for name in sorted(allowed_fields)
            },
        }

    node_schemas = []
    for protocol in sorted(PUBLIC_PROTOCOLS, key=lambda item: item.value):
        descriptor = protocol_registry.get(protocol)
        if descriptor is None:
            raise ValueError(f"Protocol has no registered node model: {protocol.value}")
        hints = get_type_hints(descriptor.node_class)
        properties = {
            name: _json_schema_for_type(hints[name])
            for name in sorted(public_node_fields(protocol) - {"type"})
        }
        properties["type"] = {"const": protocol.value}
        node_schemas.append(
            {
                "title": protocol.value,
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "type"],
                "properties": properties,
            }
        )

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/ekkog/subio/schemas/subio-node-v1.schema.json",
        "title": "SubIO node document v1",
        "type": "object",
        "additionalProperties": False,
        "required": ["version", "nodes"],
        "properties": {
            "version": {"const": SUBIO_FORMAT_VERSION},
            "nodes": {"type": "array", "items": {"oneOf": node_schemas}},
        },
        "$defs": definitions,
    }


def _json_schema_for_type(expected: Any) -> dict[str, Any]:
    if expected is Any:
        return {"$ref": "#/$defs/jsonValue"}
    origin = get_origin(expected)
    args = get_args(expected)
    if origin in {Union, types.UnionType}:
        alternatives = [arg for arg in args if arg is not type(None)]
        schemas = [_json_schema_for_type(alternative) for alternative in alternatives]
        return schemas[0] if len(schemas) == 1 else {"anyOf": schemas}
    if origin is list:
        return {
            "type": "array",
            "items": _json_schema_for_type(args[0] if args else Any),
        }
    if origin is dict:
        key_type, value_type = args or (str, Any)
        if key_type not in {str, Any}:
            raise ValueError(f"SubIO schema only supports string object keys: {expected}")
        return {
            "type": "object",
            "additionalProperties": _json_schema_for_type(value_type),
        }
    if isinstance(expected, type) and issubclass(expected, StrEnum):
        return {"type": "string", "enum": [item.value for item in expected]}
    if isinstance(expected, type) and expected in PUBLIC_NESTED_FIELDS:
        return {"$ref": f"#/$defs/{expected.__name__}"}
    if expected is bool:
        return {"type": "boolean"}
    if expected is int:
        return {"type": "integer"}
    if expected is str:
        return {"type": "string"}
    raise ValueError(f"Unsupported SubIO schema type: {expected}")


def write_json_schema(path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(build_json_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the SubIO node v1 schema")
    parser.add_argument("path", help="Output JSON schema path")
    args = parser.parse_args()
    write_json_schema(args.path)


if __name__ == "__main__":
    main()
