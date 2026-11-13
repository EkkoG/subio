from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    _parameter_bool,
    _server_str,
    _surge_tls,
    _validate_opaque_endpoint,
)
from subio_v2.adapters.surge.syntax import SurgeProxyRecord
from subio_v2.core.nodes import (
    Node,
    Protocol,
    TrustTunnelNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_trusttunnel(record: SurgeProxyRecord) -> TrustTunnelNode:
    _validate_opaque_endpoint(record)
    values = record.parameters.last_values
    if not values.get("username") or not values.get("password"):
        raise ValueError("username and password are required")
    h3 = _parameter_bool(values, "h3")
    websocket = _parameter_bool(values, "ws")
    if h3 and websocket:
        raise ValueError("h3 and ws cannot be enabled together")
    max_streams = (
        int(values["max-streams"]) if values.get("max-streams") is not None else None
    )
    if max_streams is not None and max_streams <= 0:
        raise ValueError("max-streams must be positive")
    node = TrustTunnelNode(
        name=record.name,
        type=Protocol.TRUSTTUNNEL,
        server=record.positional[0],
        port=int(record.positional[1]),
        udp=False,
        username=values["username"],
        password=values["password"],
        headers=values.get("headers"),
        max_streams=max_streams,
        quic=h3,
        websocket=websocket,
        tls=_surge_tls(values),
    )
    return node


def check_trusttunnel(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, TrustTunnelNode):
        return []
    warnings: list[IssueDraft] = []
    if node.udp:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Surge Trust Tunnel does not support UDP",
                field="udp",
                code="conversion.unsupported-protocol-variant",
            )
        )
    for field, value in (
        ("health_check", node.health_check),
        ("congestion_controller", node.congestion_controller),
        ("cwnd", node.cwnd),
        ("bbr_profile", node.bbr_profile),
        ("max_connections", node.max_connections),
        ("min_streams", node.min_streams),
        ("client_fingerprint", node.tls.client_fingerprint),
    ):
        if value:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.WARNING,
                    message=f"Trust Tunnel field '{field}' is Mihomo-only",
                    field=field,
                    code="conversion.unconsumed-source-field",
                )
            )
    for field, value in (
        ("ech_opts", node.tls.ech_opts),
        ("certificate", node.tls.certificate),
        ("private_key", node.tls.private_key),
    ):
        if value:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Trust Tunnel TLS field '{field}' cannot be represented by Surge",
                    field=f"tls.{field}",
                    code="conversion.unconsumed-source-field",
                )
            )
    return warnings


def emit_trust_tunnel(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, TrustTunnelNode)
    parts = [
        "trust-tunnel",
        _server_str(node),
        str(node.port),
        f"username={node.username}",
        f"password={node.password}",
    ]
    if node.headers:
        parts.append(f"headers={node.headers}")
    if node.max_streams is not None:
        parts.append(f"max-streams={node.max_streams}")
    if node.quic:
        parts.append("h3=true")
    if node.websocket:
        parts.append("ws=true")
    return parts


CODECS = (
    _spec(
        "trust-tunnel",
        protocol=Protocol.TRUSTTUNNEL,
        check=check_trusttunnel,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        parser=parse_trusttunnel,
        emitter=emit_trust_tunnel,
        consumed=("username", "password", "headers", "max-streams", "h3", "ws"),
    ),
)
