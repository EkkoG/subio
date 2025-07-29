"""Snell protocol parser for Clash."""

from typing import Dict, Any, Optional
from ....models.node import Proxy, SnellProtocol
from .registry import register_clash_parser


@register_clash_parser("snell")
def parse_snell(data: Dict[str, Any]) -> Optional[Proxy]:
    """Parse Snell proxy configuration."""
    try:
        # Parse obfs options
        obfs_mode = None
        obfs_host = None
        if data.get("obfs-opts"):
            obfs_opts = data["obfs-opts"]
            obfs_mode = obfs_opts.get("mode")
            obfs_host = obfs_opts.get("host")

        protocol = SnellProtocol(
            psk=data.get("psk", ""),
            version=data.get("version", 2),
            obfs_mode=obfs_mode,
            obfs_host=obfs_host,
        )

        node = Proxy(
            name=data.get("name", "snell"),
            server=data.get("server", ""),
            port=data.get("port", 443),
            protocol=protocol,
        )

        # Validate protocol
        try:
            protocol.validate()
        except ValueError as e:
            print(f"Snell validation error: {e}")
            return None

        return node
    except Exception as e:
        print(f"Failed to parse Snell proxy: {e}")
        return None
