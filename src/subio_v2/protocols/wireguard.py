from __future__ import annotations

from typing import Any, Dict, List

from subio_v2.clash.helpers import (
    assign_extra,
    emit_base,
    emit_smux,
    merge_extra,
    parse_base_fields,
    parse_smux,
)
from subio_v2.model.nodes import Node, Protocol, WireguardNode
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class WireguardDescriptor(ProtocolDescriptor):
    protocol = Protocol.WIREGUARD
    clash_type = "wireguard"
    node_class = WireguardNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        ip_val = data.get("ip")
        allowed_ips: List[str] = []
        interface_ip = ip_val
        if isinstance(ip_val, list):
            allowed_ips = list(ip_val)
        elif ip_val:
            interface_ip = ip_val

        if data.get("allowed-ips"):
            allowed_ips = list(data["allowed-ips"])

        handled = {
            "private-key",
            "public-key",
            "preshared-key",
            "pre-shared-key",
            "ip",
            "ipv6",
            "allowed-ips",
            "reserved",
            "mtu",
            "workers",
            "persistent-keepalive",
            "amnezia-wg-option",
            "peers",
            "remote-dns-resolve",
            "dns",
            "refresh-server-ip-interval",
            "smux",
        }
        node = WireguardNode(
            type=Protocol.WIREGUARD,
            private_key=data.get("private-key", ""),
            public_key=data.get("public-key", ""),
            preshared_key=data.get("preshared-key") or data.get("pre-shared-key"),
            interface_ip=interface_ip,
            interface_ipv6=data.get("ipv6"),
            allowed_ips=allowed_ips or ["0.0.0.0/0", "::/0"],
            reserved=data.get("reserved"),
            mtu=data.get("mtu"),
            workers=data.get("workers"),
            persistent_keepalive=data.get("persistent-keepalive"),
            amnezia_wg_option=data.get("amnezia-wg-option"),
            peers=data.get("peers"),
            remote_dns_resolve=data.get("remote-dns-resolve"),
            dns_servers=data.get("dns"),
            refresh_server_ip_interval=data.get("refresh-server-ip-interval"),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, WireguardNode):
            raise TypeError(f"Expected WireguardNode, got {type(node)}")
        base = emit_base(node)
        base["private-key"] = node.private_key
        base["udp"] = True
        if node.public_key:
            base["public-key"] = node.public_key
        if node.preshared_key:
            base["preshared-key"] = node.preshared_key
        if node.interface_ip is not None:
            base["ip"] = node.interface_ip
        elif node.allowed_ips and len(node.allowed_ips) > 1:
            base["ip"] = node.allowed_ips
        elif node.allowed_ips:
            base["ip"] = node.allowed_ips[0]
        if node.interface_ipv6 is not None:
            base["ipv6"] = node.interface_ipv6
        if node.allowed_ips and node.interface_ip is None:
            pass
        elif node.allowed_ips and isinstance(node.interface_ip, list):
            if node.allowed_ips != list(node.interface_ip):
                base["allowed-ips"] = node.allowed_ips
        if node.reserved:
            base["reserved"] = node.reserved
        if node.mtu is not None:
            base["mtu"] = node.mtu
        if node.workers is not None:
            base["workers"] = node.workers
        if node.persistent_keepalive is not None:
            base["persistent-keepalive"] = node.persistent_keepalive
        if node.amnezia_wg_option:
            base["amnezia-wg-option"] = node.amnezia_wg_option
        if node.peers:
            base["peers"] = node.peers
        if node.remote_dns_resolve is not None:
            base["remote-dns-resolve"] = node.remote_dns_resolve
        if node.dns_servers:
            base["dns"] = node.dns_servers
        if node.refresh_server_ip_interval is not None:
            base["refresh-server-ip-interval"] = node.refresh_server_ip_interval
        emit_smux(base, node.smux)
        return merge_extra(base, node)


register(WireguardDescriptor())
