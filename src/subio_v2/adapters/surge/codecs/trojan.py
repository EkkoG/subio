from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    SurgeProtocolParseContext,
    _serialize_headers,
    _server_str,
)
from subio_v2.core.nodes import (
    Network,
    Node,
    Protocol,
    TrojanNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_trojan(context: SurgeProtocolParseContext) -> Node:
    return TrojanNode(
        name=context.record.name,
        type=Protocol.TROJAN,
        server=context.server,
        port=context.port,
        password=context.values.get("password", ""),
        tls=context.build_tls(enabled=True),
        transport=context.build_transport(),
        udp=True,
    )


def check_trojan(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, TrojanNode):
        return []
    warnings: list[IssueDraft] = []
    supported_transports = proto_caps.get("transports", set())
    network = node.transport.network_value if node.transport else "tcp"
    if supported_transports and network not in supported_transports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Transport '{network}' is not supported by surge",
                field="transport.network",
                suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}",
            )
        )
    if (
        node.smux
        and node.smux.enabled
        and ("smux" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.WARNING,
                message="SMUX is not supported by surge, will be ignored",
                field="smux",
            )
        )
    if (
        node.tls
        and node.tls.reality_opts
        and ("reality" not in proto_caps.get("features", set()))
    ):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Reality is not supported for Trojan on surge",
                field="reality",
            )
        )
    return warnings


def emit_trojan(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, TrojanNode)
    parts = [
        "trojan",
        _server_str(node),
        str(node.port),
        f"password={node.password}",
    ]
    if node.transport.network == Network.WS:
        parts.append("ws=true")
        if node.transport.path:
            parts.append(f"ws-path={node.transport.path}")
        if node.transport.headers:
            headers = _serialize_headers(
                node.transport.headers, separator="|", field="transport.headers"
            )
            parts.append(f"ws-headers={headers}")
    return parts


CODECS = (
    _spec(
        "trojan",
        protocol=Protocol.TROJAN,
        check=check_trojan,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_trojan,
        emitter=emit_trojan,
        consumed=("password", "ws", "ws-path", "ws-headers"),
        constraints={"transports": {"tcp", "ws"}},
    ),
)
