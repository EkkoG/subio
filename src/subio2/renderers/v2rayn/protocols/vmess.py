"""VMess renderer for V2rayN format."""

import base64
import json
from ....models.node import Proxy, VmessProtocol
from .registry import v2rayn_protocol_registry


@v2rayn_protocol_registry.register("vmess")
def render(node: Proxy) -> str:
    """Render VMess node to V2rayN URL format."""
    protocol = node.protocol
    if not isinstance(protocol, VmessProtocol):
        return ""

    # Build VMess JSON object
    vmess_obj = {
        "v": "2",
        "ps": node.name,
        "add": node.server,
        "port": str(node.port),
        "id": protocol.uuid,
        "aid": str(protocol.alter_id),
        "scy": protocol.security,
        "net": "tcp",
        "type": "none",
        "host": "",
        "path": "",
        "tls": "",
        "sni": "",
        "alpn": "",
        "fp": "",
    }

    # Handle TLS
    if node.tls and node.tls.enabled:
        vmess_obj["tls"] = "tls"
        if node.tls.sni:
            vmess_obj["sni"] = node.tls.sni

    # Handle transport
    if node.transport:
        vmess_obj["net"] = node.transport.type

        if (
            node.transport.type == "ws"
            and hasattr(node.transport, "ws")
            and node.transport.ws
        ):
            ws = node.transport.ws
            vmess_obj["path"] = ws.path or "/"
            if ws.headers and "Host" in ws.headers:
                vmess_obj["host"] = ws.headers["Host"]
        elif (
            node.transport.type == "grpc"
            and hasattr(node.transport, "grpc")
            and node.transport.grpc
        ):
            grpc = node.transport.grpc
            vmess_obj["path"] = grpc.service_name

    # Encode to base64
    json_str = json.dumps(vmess_obj, separators=(",", ":"))
    encoded = base64.b64encode(json_str.encode()).decode()

    return f"vmess://{encoded}"
