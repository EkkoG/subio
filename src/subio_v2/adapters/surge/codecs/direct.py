from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.syntax import SurgeProxyRecord
from subio_v2.core.nodes import (
    DirectNode,
    Node,
    Protocol,
)


def parse_direct(record: SurgeProxyRecord) -> DirectNode:
    return DirectNode(
        name=record.name,
        type=Protocol.DIRECT,
        server=None,
        port=None,
        udp=True,
    )


def emit_direct(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, DirectNode)
    return ["direct"]


CODECS = (
    _spec(
        "direct",
        protocol=Protocol.DIRECT,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_direct,
        emitter=emit_direct,
    ),
)
