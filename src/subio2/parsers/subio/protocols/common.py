"""Common utilities for SubIO protocol parsers."""

from typing import Dict, Any, Optional
from ....models.node import (
    Proxy,
    BasicAuth,
    TLSConfig,
    WebSocketTransport,
    GRPCTransport,
)


def parse_transport(transport_type: str, node_data: Dict[str, Any]) -> Optional[Any]:
    """Parse transport configuration."""
    if transport_type == "ws" or transport_type == "websocket":
        return WebSocketTransport(
            path=node_data.get("ws_path", node_data.get("path", "/")),
            headers=node_data.get("ws_headers", node_data.get("headers", {})),
        )

    elif transport_type == "grpc":
        return GRPCTransport(
            service_name=node_data.get(
                "grpc_service_name", node_data.get("service_name", "")
            )
        )

    return None


def add_common_fields(node: Proxy, node_data: Dict[str, Any]):
    """Add common fields like auth, transport, TLS to a node."""
    node_type = node_data.get("type", "").lower()

    # Add auth for HTTP/SOCKS5
    if node_type in ["http", "socks5", "socks"]:
        username = node_data.get("username")
        password = node_data.get("password")
        if username and password:
            node.auth = BasicAuth(username=username, password=password)

    # Add transport if specified
    transport_type = node_data.get("transport", node_data.get("network"))
    if transport_type:
        transport = parse_transport(transport_type, node_data)
        if transport:
            node.transport = transport

    # Add TLS config
    if node_data.get("tls"):
        node.tls = TLSConfig(
            enabled=True,
            skip_cert_verify=node_data.get(
                "skip_cert_verify", node_data.get("skip-cert-verify", False)
            ),
            sni=node_data.get("sni", node_data.get("servername")),
        )

    # Add extra metadata
    if node_data.get("udp"):
        node.extra["udp"] = True
