"""Shared Clash/Mihomo proxy parse and emit helpers (aligned with meta-json-schema)."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Set

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
    net = data.get("network", "tcp")
    network = Network(net) if net in [n.value for n in Network] else Network.TCP
    return TransportSettings(
        network=network,
        path=data.get("ws-opts", {}).get("path")
        or data.get("h2-opts", {}).get("path")
        or data.get("http-opts", {}).get("path"),
        headers=data.get("ws-opts", {}).get("headers")
        or data.get("http-opts", {}).get("headers"),
        host=data.get("h2-opts", {}).get("host"),
        method=data.get("http-opts", {}).get("method"),
        grpc_service_name=data.get("grpc-opts", {}).get("grpc-service-name"),
        max_early_data=data.get("ws-opts", {}).get("max-early-data"),
        early_data_header_name=data.get("ws-opts", {}).get("early-data-header-name"),
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


def emit_transport(base: Dict[str, Any], transport: Optional[TransportSettings]) -> None:
    if not transport or transport.network == Network.TCP:
        return
    base["network"] = transport.network.value
    if transport.network == Network.WS:
        opts: Dict[str, Any] = {}
        if transport.path:
            opts["path"] = transport.path
        if transport.headers:
            opts["headers"] = transport.headers
        if transport.max_early_data is not None:
            opts["max-early-data"] = transport.max_early_data
        if transport.early_data_header_name:
            opts["early-data-header-name"] = transport.early_data_header_name
        if opts:
            base["ws-opts"] = opts
    elif transport.network == Network.HTTP:
        opts = {}
        if transport.method:
            opts["method"] = transport.method
        if transport.path:
            opts["path"] = (
                [transport.path] if isinstance(transport.path, str) else transport.path
            )
        if transport.headers:
            opts["headers"] = transport.headers
        if opts:
            base["http-opts"] = opts
    elif transport.network == Network.H2:
        opts = {}
        if transport.host:
            opts["host"] = transport.host
        if transport.path:
            opts["path"] = transport.path
        if opts:
            base["h2-opts"] = opts
    elif transport.network == Network.GRPC:
        opts = {}
        if transport.grpc_service_name:
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
