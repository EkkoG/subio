from __future__ import annotations

from dataclasses import dataclass

from subio_v2.model.nodes import (
    AnyTLSNode,
    BaseNode,
    DirectNode,
    DNSNode,
    GostRelayNode,
    HttpNode,
    Hysteria2Node,
    HysteriaNode,
    JuicityNode,
    MasqueNode,
    MieruNode,
    OpenVPNNode,
    Protocol,
    RejectNode,
    RematchNode,
    ShadowQUICNode,
    ShadowsocksNode,
    ShadowsocksRNode,
    SnellNode,
    Socks5Node,
    SSHNode,
    SudokuNode,
    TailscaleNode,
    TrojanNode,
    TrustTunnelNode,
    TUICNode,
    VlessNode,
    VmessNode,
    WireguardNode,
)


@dataclass(frozen=True)
class ProtocolDefinition:
    protocol: Protocol
    node_class: type[BaseNode]
    requires_endpoint: bool = True
    user_override_fields: frozenset[str] = frozenset()
    terminal_native_fields: frozenset[str] = frozenset()
    terminal_native_excluded_fields: frozenset[str] = frozenset()


TERMINAL_NATIVE_COMMON_FIELDS = frozenset(
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
TERMINAL_NATIVE_COMMON_EXCLUDED_FIELDS = frozenset({"record"})


_RUNTIME_USER_OVERRIDE_FIELDS: dict[Protocol, frozenset[str]] = {
    Protocol.ANYTLS: frozenset({"server", "port", "password"}),
    Protocol.DIRECT: frozenset({"server", "port"}),
    Protocol.DNS: frozenset({"server", "port"}),
    Protocol.GOST_RELAY: frozenset({"server", "port", "username", "password"}),
    Protocol.HTTP: frozenset({"server", "port", "username", "password"}),
    Protocol.HYSTERIA: frozenset({"server", "port", "auth", "auth_str"}),
    Protocol.HYSTERIA2: frozenset({"server", "port", "password", "obfs_password"}),
    Protocol.JUICITY: frozenset({"server", "port", "uuid", "password"}),
    Protocol.MASQUE: frozenset(
        {
            "server",
            "port",
            "username",
            "password",
            "private_key",
            "public_key",
        }
    ),
    Protocol.MIERU: frozenset({"server", "port", "username", "password"}),
    Protocol.OPENVPN: frozenset(
        {
            "server",
            "port",
            "username",
            "password",
            "auth",
            "cipher",
            "private_key",
        }
    ),
    Protocol.REJECT: frozenset({"server", "port"}),
    Protocol.REMATCH: frozenset({"server", "port"}),
    Protocol.SHADOWQUIC: frozenset({"server", "port", "username", "password"}),
    Protocol.SHADOWSOCKS: frozenset({"server", "port", "cipher", "password"}),
    Protocol.SHADOWSOCKSR: frozenset({"server", "port", "cipher", "password"}),
    Protocol.SNELL: frozenset({"server", "port", "psk"}),
    Protocol.SOCKS5: frozenset({"server", "port", "username", "password"}),
    Protocol.SSH: frozenset(
        {
            "server",
            "port",
            "username",
            "password",
            "private_key",
            "private_key_passphrase",
        }
    ),
    Protocol.SUDOKU: frozenset({"server", "port"}),
    Protocol.TAILSCALE: frozenset({"server", "port", "auth_key"}),
    Protocol.TROJAN: frozenset({"server", "port", "password"}),
    Protocol.TRUSTTUNNEL: frozenset({"server", "port", "username", "password"}),
    Protocol.TUIC: frozenset({"server", "port", "token", "uuid", "password"}),
    Protocol.VLESS: frozenset({"server", "port", "uuid"}),
    Protocol.VMESS: frozenset({"server", "port", "uuid", "alter_id", "cipher"}),
    Protocol.WIREGUARD: frozenset(
        {"server", "port", "private_key", "public_key", "preshared_key"}
    ),
}

_TERMINAL_NATIVE_FIELDS: dict[Protocol, frozenset[str]] = {
    Protocol.ANYTLS: frozenset(
        {
            "idle_session_check_interval",
            "idle_session_timeout",
            "min_idle_session",
            "password",
            "reuse",
            "tls",
        }
    ),
    Protocol.DIRECT: frozenset({"smux"}),
    Protocol.DNS: frozenset({"smux"}),
    Protocol.GOST_RELAY: frozenset(
        {"forward", "mux", "password", "smux", "tls", "username"}
    ),
    Protocol.HTTP: frozenset(
        {"headers", "max_streams", "password", "tls", "username", "variant"}
    ),
    Protocol.HYSTERIA: frozenset(
        {
            "auth",
            "auth_str",
            "down",
            "down_speed",
            "hop_interval",
            "hysteria_protocol",
            "obfs",
            "obfs_protocol",
            "ports",
            "smux",
            "tls",
            "up",
            "up_speed",
        }
    ),
    Protocol.HYSTERIA2: frozenset(
        {
            "down",
            "hop_interval",
            "obfs",
            "obfs_password",
            "password",
            "ports",
            "smux",
            "tls",
            "up",
        }
    ),
    Protocol.JUICITY: frozenset({"password", "tls", "uuid"}),
    Protocol.MASQUE: frozenset(
        {
            "bbr_profile",
            "congestion_controller",
            "connect_uri",
            "cwnd",
            "dns_servers",
            "handshake_timeout",
            "hop_interval",
            "interface_ip",
            "interface_ipv6",
            "mode",
            "mtu",
            "password",
            "ports",
            "private_key",
            "public_key",
            "remote_dns_resolve",
            "smux",
            "tls",
            "transport",
            "username",
        }
    ),
    Protocol.MIERU: frozenset(
        {
            "handshake_mode",
            "multiplexing",
            "password",
            "port_range",
            "smux",
            "traffic_pattern",
            "transport",
            "username",
        }
    ),
    Protocol.OPENVPN: frozenset(
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
    Protocol.REJECT: frozenset({"mode", "smux"}),
    Protocol.REMATCH: frozenset({"smux", "target_rematch_name", "target_sub_rule"}),
    Protocol.SHADOWQUIC: frozenset(
        {
            "bbr_profile",
            "congestion_controller",
            "cwnd",
            "disable_mtu_discovery",
            "down",
            "keep_alive_interval",
            "max_datagram_frame_size",
            "max_open_streams",
            "password",
            "quic_versions",
            "recv_window",
            "recv_window_conn",
            "smux",
            "tls",
            "udp_over_stream",
            "up",
            "username",
            "zero_rtt",
        }
    ),
    Protocol.SHADOWSOCKS: frozenset(
        {"cipher", "password", "plugin", "plugin_opts", "smux", "udp_port"}
    ),
    Protocol.SHADOWSOCKSR: frozenset(
        {
            "cipher",
            "obfs",
            "obfs_param",
            "password",
            "protocol_param",
            "smux",
            "ssr_protocol",
        }
    ),
    Protocol.SNELL: frozenset(
        {
            "mode",
            "obfs",
            "obfs_host",
            "obfs_opts",
            "psk",
            "reuse",
            "smux",
            "tls",
            "udp_port",
            "version",
        }
    ),
    Protocol.SOCKS5: frozenset({"password", "tls", "username"}),
    Protocol.SSH: frozenset(
        {
            "host_key",
            "host_key_algorithms",
            "idle_timeout",
            "password",
            "private_key",
            "private_key_passphrase",
            "server_fingerprints",
            "username",
        }
    ),
    Protocol.SUDOKU: frozenset(
        {
            "aead_method",
            "custom_table",
            "custom_tables",
            "enable_pure_downlink",
            "httpmask",
            "key",
            "legacy_http_mask",
            "legacy_http_mask_host",
            "legacy_http_mask_mode",
            "legacy_http_mask_multiplex",
            "legacy_http_mask_strategy",
            "legacy_http_mask_tls",
            "legacy_path_root",
            "multiplex",
            "padding_max",
            "padding_min",
            "smux",
            "table_type",
        }
    ),
    Protocol.TAILSCALE: frozenset(
        {
            "accept_routes",
            "auth_key",
            "auto_add_magic_dns_rule",
            "control_url",
            "derp_only",
            "dns_servers",
            "ephemeral",
            "exit_node",
            "exit_node_allow_lan_access",
            "exit_node_auto_fallback",
            "hostname",
            "idle_keepalive",
            "mtu",
            "prefer_ipv6",
            "smux",
            "state_dir",
        }
    ),
    Protocol.TROJAN: frozenset({"password", "smux", "tls", "transport"}),
    Protocol.TRUSTTUNNEL: frozenset(
        {
            "bbr_profile",
            "congestion_controller",
            "cwnd",
            "headers",
            "health_check",
            "max_connections",
            "max_streams",
            "min_streams",
            "password",
            "quic",
            "smux",
            "tls",
            "username",
            "websocket",
        }
    ),
    Protocol.TUIC: frozenset(
        {"hop_interval", "password", "ports", "smux", "tls", "token", "uuid", "version"}
    ),
    Protocol.VLESS: frozenset(
        {"flow", "packet_encoding", "smux", "tls", "transport", "uuid"}
    ),
    Protocol.VMESS: frozenset(
        {
            "alter_id",
            "cipher",
            "global_padding",
            "packet_encoding",
            "smux",
            "tls",
            "transport",
            "uuid",
            "vmess_aead",
        }
    ),
    Protocol.WIREGUARD: frozenset(
        {
            "allowed_ips",
            "amnezia_wg_option",
            "dns_servers",
            "interface_ip",
            "interface_ipv6",
            "mtu",
            "peers",
            "persistent_keepalive",
            "preshared_key",
            "private_key",
            "public_key",
            "refresh_server_ip_interval",
            "remote_dns_resolve",
            "reserved",
            "smux",
            "workers",
        }
    ),
}

_TERMINAL_NATIVE_EXCLUDED_FIELDS: dict[Protocol, frozenset[str]] = {
    Protocol.SSH: frozenset({"keystore_id"}),
    Protocol.TAILSCALE: frozenset({"interactive_login"}),
}


def _definition(
    protocol: Protocol,
    node_class: type[BaseNode],
    *,
    requires_endpoint: bool = True,
) -> ProtocolDefinition:
    return ProtocolDefinition(
        protocol=protocol,
        node_class=node_class,
        requires_endpoint=requires_endpoint,
        user_override_fields=_RUNTIME_USER_OVERRIDE_FIELDS[protocol],
        terminal_native_fields=_TERMINAL_NATIVE_FIELDS[protocol],
        terminal_native_excluded_fields=_TERMINAL_NATIVE_EXCLUDED_FIELDS.get(
            protocol, frozenset()
        ),
    )


_DEFINITIONS = (
    _definition(Protocol.SHADOWSOCKS, ShadowsocksNode),
    _definition(Protocol.SHADOWSOCKSR, ShadowsocksRNode),
    _definition(Protocol.VMESS, VmessNode),
    _definition(Protocol.VLESS, VlessNode),
    _definition(Protocol.TROJAN, TrojanNode),
    _definition(Protocol.SOCKS5, Socks5Node),
    _definition(Protocol.HTTP, HttpNode),
    _definition(Protocol.WIREGUARD, WireguardNode),
    _definition(Protocol.TAILSCALE, TailscaleNode, requires_endpoint=False),
    _definition(Protocol.MASQUE, MasqueNode),
    _definition(Protocol.TRUSTTUNNEL, TrustTunnelNode),
    _definition(Protocol.DIRECT, DirectNode, requires_endpoint=False),
    _definition(Protocol.DNS, DNSNode, requires_endpoint=False),
    _definition(Protocol.REMATCH, RematchNode, requires_endpoint=False),
    _definition(Protocol.GOST_RELAY, GostRelayNode),
    _definition(Protocol.SHADOWQUIC, ShadowQUICNode),
    _definition(Protocol.OPENVPN, OpenVPNNode),
    _definition(Protocol.SUDOKU, SudokuNode),
    _definition(Protocol.REJECT, RejectNode, requires_endpoint=False),
    _definition(Protocol.ANYTLS, AnyTLSNode),
    _definition(Protocol.HYSTERIA, HysteriaNode),
    _definition(Protocol.HYSTERIA2, Hysteria2Node),
    _definition(Protocol.SSH, SSHNode),
    _definition(Protocol.SNELL, SnellNode),
    _definition(Protocol.MIERU, MieruNode, requires_endpoint=False),
    _definition(Protocol.JUICITY, JuicityNode),
    _definition(Protocol.TUIC, TUICNode),
)

_BY_PROTOCOL = {definition.protocol: definition for definition in _DEFINITIONS}
if len(_BY_PROTOCOL) != len(_DEFINITIONS):
    raise ValueError("Protocol definitions must use unique protocol IDs")


def get_definition(protocol: Protocol) -> ProtocolDefinition | None:
    return _BY_PROTOCOL.get(protocol)


def all_definitions() -> tuple[ProtocolDefinition, ...]:
    return _DEFINITIONS
