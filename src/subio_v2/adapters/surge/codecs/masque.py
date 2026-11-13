from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    _server_str,
    _surge_tls,
    _validate_opaque_endpoint,
)
from subio_v2.adapters.surge.syntax import SurgeProxyRecord
from subio_v2.core.nodes import (
    MasqueMode,
    MasqueNode,
    Node,
    Protocol,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_masque(record: SurgeProxyRecord) -> MasqueNode:
    _validate_opaque_endpoint(record)
    values = record.parameters.last_values
    if values.get("port-hopping") and values.get("underlying-proxy"):
        raise ValueError("port-hopping cannot be combined with underlying-proxy")
    hop_interval = (
        int(values["port-hopping-interval"])
        if values.get("port-hopping-interval") is not None
        else None
    )
    if hop_interval is not None and hop_interval <= 0:
        raise ValueError("port-hopping-interval must be positive")
    if values.get("shadow-tls-password"):
        raise ValueError("Shadow TLS cannot be combined with MASQUE")
    username = values.get("username")
    password = values.get("password")
    if bool(username) != bool(password):
        raise ValueError(
            "MASQUE Basic authentication requires both username and password"
        )
    node = MasqueNode(
        name=record.name,
        type=Protocol.MASQUE,
        server=record.positional[0],
        port=int(record.positional[1]),
        udp=True,
        mode=MasqueMode.FORWARD_PROXY,
        transport="h3",
        username=username,
        password=password,
        ports=values.get("port-hopping"),
        hop_interval=hop_interval,
        tls=_surge_tls(values),
    )
    return node


def check_masque(node: Node, constraints) -> list[IssueDraft]:
    from subio_v2.core.nodes import MasqueMode

    if node.mode != MasqueMode.FORWARD_PROXY:
        return [
            IssueDraft(
                IssueSeverity.ERROR,
                f"MASQUE mode '{node.mode.value}' is not supported by surge",
                "mode",
                code="conversion.unsupported-protocol-variant",
            )
        ]
    issues = []
    if node.transport != "h3":
        issues.append(
            IssueDraft(
                IssueSeverity.ERROR,
                f"MASQUE transport '{node.transport}' is not supported by surge",
                "transport",
                code="conversion.unsupported-protocol-variant",
            )
        )
    if node.dialer_proxy and node.ports:
        issues.append(
            IssueDraft(
                IssueSeverity.ERROR,
                "MASQUE port hopping cannot be combined with underlying-proxy",
                "ports",
                code="conversion.unsupported-field-combination",
            )
        )
    return issues


def emit_masque(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, MasqueNode)
    if node.mode != MasqueMode.FORWARD_PROXY:
        raise ValueError(f"Surge does not support MASQUE mode '{node.mode.value}'")
    parts = ["masque", _server_str(node), str(node.port)]
    if node.username:
        parts.append(f"username={node.username}")
    if node.password:
        parts.append(f"password={node.password}")
    if node.ports:
        parts.append(f"port-hopping={node.ports}")
    if node.hop_interval is not None:
        parts.append(f"port-hopping-interval={node.hop_interval}")
    return parts


CODECS = (
    _spec(
        "masque",
        protocol=Protocol.MASQUE,
        check=check_masque,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_masque,
        emitter=emit_masque,
        consumed=(
            "username",
            "password",
            "port-hopping",
            "port-hopping-interval",
        ),
    ),
)
