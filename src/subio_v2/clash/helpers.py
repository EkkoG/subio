"""Shared Clash/Mihomo proxy parse and emit helpers (aligned with meta-json-schema)."""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional, Set

from subio_v2.model.nodes import (
    Network,
    SmuxSettings,
    TLSSettings,
    TransportSettings,
)

_BASE_FIELD_KEYS = frozenset(
    {
        "name",
        "type",
        "server",
        "port",
        "udp",
        "ip-version",
        "tfo",
        "mptcp",
        "dialer-proxy",
        "users",
        "interface-name",
        "routing-mark",
    }
)


def parse_port(data: Dict[str, Any]) -> int:
    port = data.get("port", 0)
    try:
        return int(port)
    except (TypeError, ValueError) as e:
        raise ValueError(f"invalid port: {port!r}") from e


def parse_base_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    ip_version = data.get("ip-version", "dual")
    if ip_version == "dual":
        ip_version = None
    return {
        "name": data.get("name", "Unknown"),
        "server": data.get("server", "") or "",
        "port": parse_port(data),
        "udp": data.get("udp", True),
        "ip_version": ip_version,
        "tfo": bool(data.get("tfo", False)),
        "mptcp": bool(data.get("mptcp", False)),
        "dialer_proxy": data.get("dialer-proxy"),
        "users": data.get("users"),
        "interface_name": data.get("interface-name"),
        "routing_mark": data.get("routing-mark"),
    }


def assign_extra(node: Any, data: Dict[str, Any], handled: Set[str]) -> None:
    keys = handled | _BASE_FIELD_KEYS
    node.extra = {k: v for k, v in data.items() if k not in keys}


def parse_tls(data: Dict[str, Any], *, default_enabled: bool = False) -> TLSSettings:
    ech = data.get("ech-opts")
    return TLSSettings(
        enabled=bool(data.get("tls", default_enabled)),
        server_name=data.get("servername") or data.get("sni"),
        alpn=data.get("alpn"),
        skip_cert_verify=bool(data.get("skip-cert-verify", False)),
        fingerprint=data.get("fingerprint"),
        client_fingerprint=data.get("client-fingerprint"),
        reality_opts=data.get("reality-opts"),
        ech_opts=ech,
        certificate=data.get("certificate"),
        private_key=data.get("private-key"),
    )


def parse_transport(data: Dict[str, Any]) -> TransportSettings:
    net = data.get("network") or Network.TCP.value
    try:
        network: Network | str = Network(net)
    except ValueError:
        # Keep future Mihomo transports intact for Clash-to-Clash round trips.
        network = str(net)

    option_blocks: Dict[str, Dict[str, Any]] = {}
    for key in ("ws-opts", "h2-opts", "http-opts", "grpc-opts", "xhttp-opts"):
        value = data.get(key)
        if isinstance(value, dict):
            option_blocks[key] = value

    ws_opts = option_blocks.get("ws-opts", {})
    h2_opts = option_blocks.get("h2-opts", {})
    http_opts = option_blocks.get("http-opts", {})
    grpc_opts = option_blocks.get("grpc-opts", {})

    modeled_keys = {
        "ws-opts": {
            "path",
            "headers",
            "max-early-data",
            "early-data-header-name",
        },
        "h2-opts": {"path", "host"},
        "http-opts": {"path", "headers", "method"},
        "grpc-opts": {"grpc-service-name"},
        "xhttp-opts": set(),
    }
    active_option_key = {
        Network.WS.value: "ws-opts",
        Network.H2.value: "h2-opts",
        Network.HTTP.value: "http-opts",
        Network.GRPC.value: "grpc-opts",
        Network.XHTTP.value: "xhttp-opts",
    }.get(str(net))
    extra = {
        key: {
            nested_key: copy.deepcopy(nested_value)
            for nested_key, nested_value in value.items()
            if key != active_option_key or nested_key not in modeled_keys[key]
        }
        for key, value in option_blocks.items()
    }
    extra = {key: value for key, value in extra.items() if value}

    def first_present(*candidates: tuple[Dict[str, Any], str]) -> Any:
        for options, key in candidates:
            if key in options:
                return options[key]
        return None

    return TransportSettings(
        network=network,
        path=first_present((ws_opts, "path"), (h2_opts, "path"), (http_opts, "path")),
        headers=first_present((ws_opts, "headers"), (http_opts, "headers")),
        host=h2_opts.get("host"),
        method=http_opts.get("method"),
        grpc_service_name=grpc_opts.get("grpc-service-name"),
        max_early_data=ws_opts.get("max-early-data"),
        early_data_header_name=ws_opts.get("early-data-header-name"),
        extra=extra,
    )


def parse_smux(data: Dict[str, Any]) -> SmuxSettings:
    smux_data = data.get("smux") or {}
    if not smux_data:
        return SmuxSettings()
    return SmuxSettings(
        enabled=bool(smux_data.get("enabled", False)),
        protocol=smux_data.get("protocol", "smux"),
        max_connections=int(smux_data.get("max-connections", 4)),
        min_streams=int(smux_data.get("min-streams", 4)),
        max_streams=int(smux_data.get("max-streams", 0)),
        padding=bool(smux_data.get("padding", False)),
        brutal_opts=smux_data.get("brutal-opts"),
    )


def emit_base(node: Any) -> Dict[str, Any]:
    import subio_v2.protocols as protocol_registry

    desc = protocol_registry.get(node.type)
    clash_type = desc.clash_type if desc else node.type.value
    base: Dict[str, Any] = {
        "name": node.name,
        "server": node.server,
        "port": node.port,
        "type": clash_type,
        "udp": node.udp,
    }
    if node.ip_version:
        base["ip-version"] = node.ip_version
    if node.tfo:
        base["tfo"] = True
    if node.mptcp:
        base["mptcp"] = True
    if node.dialer_proxy:
        base["dialer-proxy"] = node.dialer_proxy
    if node.interface_name:
        base["interface-name"] = node.interface_name
    if node.routing_mark is not None:
        base["routing-mark"] = node.routing_mark
    if node.users:
        base["users"] = node.users
    return base


def emit_tls(base: Dict[str, Any], tls: Optional[TLSSettings]) -> None:
    if not tls or not tls.enabled:
        return
    proxy_type = base.get("type", "")
    if proxy_type not in ("anytls", "hysteria2", "tuic", "hysteria", "trusttunnel"):
        base["tls"] = True
    if tls.server_name:
        if proxy_type in ("vmess", "vless"):
            base["servername"] = tls.server_name
        else:
            base["sni"] = tls.server_name
    if tls.skip_cert_verify:
        base["skip-cert-verify"] = True
    if tls.fingerprint:
        base["fingerprint"] = tls.fingerprint
    if tls.client_fingerprint:
        base["client-fingerprint"] = tls.client_fingerprint
    if tls.alpn:
        base["alpn"] = tls.alpn
    if tls.reality_opts:
        base["reality-opts"] = tls.reality_opts
    if tls.ech_opts:
        base["ech-opts"] = tls.ech_opts
    if tls.certificate:
        base["certificate"] = tls.certificate
    if tls.private_key:
        base["private-key"] = tls.private_key


def emit_transport(
    base: Dict[str, Any], transport: Optional[TransportSettings]
) -> None:
    if not transport:
        return

    for key, value in transport.extra.items():
        base[key] = copy.deepcopy(value)

    network = transport.network_value
    if network == Network.TCP.value:
        return

    base["network"] = network
    if network == Network.WS.value:
        opts: Dict[str, Any] = copy.deepcopy(transport.extra.get("ws-opts", {}))
        if transport.path is not None:
            opts["path"] = transport.path
        if transport.headers is not None:
            opts["headers"] = transport.headers
        if transport.max_early_data is not None:
            opts["max-early-data"] = transport.max_early_data
        if transport.early_data_header_name is not None:
            opts["early-data-header-name"] = transport.early_data_header_name
        if opts:
            base["ws-opts"] = opts
    elif network == Network.HTTP.value:
        opts = copy.deepcopy(transport.extra.get("http-opts", {}))
        if transport.method is not None:
            opts["method"] = transport.method
        if transport.path is not None:
            opts["path"] = (
                [transport.path] if isinstance(transport.path, str) else transport.path
            )
        if transport.headers is not None:
            opts["headers"] = transport.headers
        if opts:
            base["http-opts"] = opts
    elif network == Network.H2.value:
        opts = copy.deepcopy(transport.extra.get("h2-opts", {}))
        if transport.host is not None:
            opts["host"] = transport.host
        if transport.path is not None:
            opts["path"] = transport.path
        if opts:
            base["h2-opts"] = opts
    elif network == Network.GRPC.value:
        opts = copy.deepcopy(transport.extra.get("grpc-opts", {}))
        if transport.grpc_service_name is not None:
            opts["grpc-service-name"] = transport.grpc_service_name
        if opts:
            base["grpc-opts"] = opts


def emit_smux(base: Dict[str, Any], smux: Optional[SmuxSettings]) -> None:
    if not smux or not smux.enabled:
        return
    payload: Dict[str, Any] = {
        "enabled": True,
        "protocol": smux.protocol,
        "max-connections": smux.max_connections,
        "min-streams": smux.min_streams,
        "max-streams": smux.max_streams,
        "padding": smux.padding,
    }
    if smux.brutal_opts:
        payload["brutal-opts"] = smux.brutal_opts
    base["smux"] = payload


def merge_extra(base: Dict[str, Any], node: Any) -> Dict[str, Any]:
    if getattr(node, "extra", None):
        for key, value in node.extra.items():
            if key not in base:
                base[key] = copy.deepcopy(value)
    return base


def emit_passthrough(node: Any) -> Dict[str, Any]:
    out = copy.deepcopy(node.raw)
    out["name"] = node.name
    if node.server:
        out["server"] = node.server
    if node.port:
        out["port"] = node.port
    if node.ip_version:
        out["ip-version"] = node.ip_version
    if node.tfo:
        out["tfo"] = True
    if node.mptcp:
        out["mptcp"] = True
    if node.dialer_proxy:
        out["dialer-proxy"] = node.dialer_proxy
    if node.interface_name:
        out["interface-name"] = node.interface_name
    if node.routing_mark is not None:
        out["routing-mark"] = node.routing_mark
    merge_extra(out, node)
    return out
