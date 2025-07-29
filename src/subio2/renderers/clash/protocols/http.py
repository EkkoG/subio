"""HTTP protocol renderer for Clash format."""

from typing import Dict, Any
from ....models.node import Proxy
from .registry import clash_renderer_registry


@clash_renderer_registry.register("http")
def render(node: Proxy) -> Dict[str, Any]:
    """Render HTTP node to Clash format."""
    result = {
        "name": node.name,
        "type": "http",
        "server": node.server,
        "port": node.port,
    }

    # Add authentication
    if node.auth:
        if node.auth.username:
            result["username"] = node.auth.username
        if node.auth.password:
            result["password"] = node.auth.password

    # Add TLS settings
    if node.tls and node.tls.enabled:
        result["tls"] = True
        if node.tls.sni:
            result["sni"] = node.tls.sni
        result["skip-cert-verify"] = node.tls.skip_cert_verify

    return result
