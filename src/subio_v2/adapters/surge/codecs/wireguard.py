from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    WireguardNode,
)


def emit_wireguard(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, WireguardNode)
    extension = node.source_extensions.get("surge", {})
    return ["wireguard", f"section-name={extension.get('section_name') or node.name}"]


CODECS = (
    _spec(
        "wireguard",
        protocol=Protocol.WIREGUARD,
        udp=SurgeUdpBehavior.AUTOMATIC,
        emitter=emit_wireguard,
        consumed=("section-name",),
    ),
)
