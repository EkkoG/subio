"""WireGuard protocol parser for Clash."""

from typing import Dict, Any, Optional
from ....models.node import Proxy, WireGuardProtocol
from .registry import register_clash_parser


@register_clash_parser("wireguard")
@register_clash_parser("wg")
def parse_wireguard(data: Dict[str, Any]) -> Optional[Proxy]:
    """Parse WireGuard proxy configuration."""
    try:
        protocol = WireGuardProtocol(
            private_key=data.get("private-key", ""),
            public_key=data.get("public-key", ""),
            preshared_key=data.get("pre-shared-key") or data.get("preshared-key"),
            ip=data.get("ip"),
            ipv6=data.get("ipv6"),
            reserved=data.get("reserved"),
            mtu=data.get("mtu"),
        )

        node = Proxy(
            name=data.get("name", "wireguard"),
            server=data.get("server", ""),
            port=data.get("port", 51820),
            protocol=protocol,
        )

        # Handle UDP
        node.extra["udp"] = data.get("udp", True)

        # Handle DNS
        if data.get("dns"):
            node.extra["dns"] = data["dns"]

        # Handle peers (if present)
        if data.get("peers"):
            node.extra["peers"] = data["peers"]

        # Handle dialer-proxy
        if data.get("dialer-proxy"):
            node.extra["dialer-proxy"] = data["dialer-proxy"]

        # Handle remote-dns-resolve
        if data.get("remote-dns-resolve"):
            node.extra["remote-dns-resolve"] = data["remote-dns-resolve"]

        # Handle refresh-server-ip-interval
        if data.get("refresh-server-ip-interval"):
            node.extra["refresh-server-ip-interval"] = data[
                "refresh-server-ip-interval"
            ]

        # Validate protocol
        try:
            protocol.validate()
        except ValueError as e:
            print(f"WireGuard validation error: {e}")
            return None

        return node
    except Exception as e:
        print(f"Failed to parse WireGuard proxy: {e}")
        return None
