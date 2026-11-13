from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    SurgeProtocolParseContext,
    _server_str,
)
from subio_v2.core.nodes import (
    AnyTLSNode,
    Node,
    Protocol,
)


def parse_anytls(context: SurgeProtocolParseContext) -> Node:
    return AnyTLSNode(
        name=context.record.name,
        type=Protocol.ANYTLS,
        server=context.server,
        port=context.port,
        password=context.values.get("password", ""),
        reuse=context.get_bool("reuse", True),
        tls=context.build_tls(enabled=True),
        udp=True,
    )


def emit_anytls(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, AnyTLSNode)
    parts = ["anytls", _server_str(node), str(node.port), f"password={node.password}"]
    if not node.reuse:
        parts.append("reuse=false")
    return parts


CODECS = (
    _spec(
        "anytls",
        protocol=Protocol.ANYTLS,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_anytls,
        emitter=emit_anytls,
        consumed=("password", "reuse"),
    ),
)
