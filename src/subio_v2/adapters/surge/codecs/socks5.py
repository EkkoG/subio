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
    Node,
    Protocol,
    Socks5Node,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_socks5(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    positional = context.positional
    username = values.get("username") or (positional[0] if positional else None)
    password = values.get("password") or (
        positional[1] if len(positional) > 1 else None
    )
    return Socks5Node(
        name=context.record.name,
        type=Protocol.SOCKS5,
        server=context.server,
        port=context.port,
        username=username,
        password=password,
        tls=context.build_tls(enabled=context.keyword == "socks5-tls"),
        udp=context.get_bool("udp-relay", False),
    )


def check_socks5(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, Socks5Node):
        return []
    if not node.tls or not node.tls.enabled:
        return []
    if "tls" in proto_caps.get("features", set()):
        return []
    return [
        IssueDraft(
            severity=IssueSeverity.ERROR,
            message="SOCKS5 TLS is not supported by surge",
            field="tls",
        )
    ]


def emit_socks5(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, Socks5Node)
    proxy_type = "socks5-tls" if node.tls.enabled else "socks5"
    parts = [proxy_type, _server_str(node), str(node.port)]
    if node.username:
        parts.append(f"username={node.username}")
    if node.password:
        parts.append(f"password={node.password}")
    return parts


CODECS = (
    _spec(
        "socks5",
        protocol=Protocol.SOCKS5,
        check=check_socks5,
        udp=SurgeUdpBehavior.EXPLICIT,
        parser=parse_socks5,
        emitter=emit_socks5,
        consumed=("username", "password", "udp-relay"),
        constraints={"features": {"tls"}},
    ),
    _spec(
        "socks5-tls",
        protocol=Protocol.SOCKS5,
        check=check_socks5,
        udp=SurgeUdpBehavior.EXPLICIT,
        parser=parse_socks5,
        emitter=emit_socks5,
        consumed=("username", "password", "udp-relay"),
        constraints={"features": {"tls"}},
    ),
)
