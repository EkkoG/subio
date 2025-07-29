"""SSH protocol renderer for Clash."""

from typing import Dict, Any
from ....models.node import Proxy, SSHProtocol
from .registry import register_clash_renderer


@register_clash_renderer("ssh")
def render_ssh(node: Proxy) -> Dict[str, Any]:
    """Render SSH proxy configuration."""
    protocol = node.protocol
    if not isinstance(protocol, SSHProtocol):
        return {}

    # Use the generic to_dict method which handles all fields properly
    result = node.to_dict()

    # SSH specific adjustments
    # Ensure type is correctly set
    result["type"] = "ssh"

    return result
