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
    TUICNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_tuic(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    try:
        version = (
            5
            if context.keyword == "tuic-v5"
            else (int(values["version"]) if values.get("version") else None)
        )
    except (TypeError, ValueError):
        version = None
    return TUICNode(
        name=context.record.name,
        type=Protocol.TUIC,
        server=context.server,
        port=context.port,
        token=values.get("token"),
        password=values.get("password"),
        uuid=values.get("uuid"),
        version=version,
        ports=values.get("port-hopping"),
        hop_interval=context.get_int("port-hopping-interval"),
        tls=context.build_tls(enabled=True),
        udp=True,
    )


def check_tuic(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, TUICNode):
        return []
    warnings: list[IssueDraft] = []
    actual_version = node.version
    if actual_version is None:
        if node.uuid or node.password:
            actual_version = 5
        elif node.token:
            actual_version = 4
    if actual_version:
        supported_versions = proto_caps.get("versions", set())
        if supported_versions and actual_version not in supported_versions:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"TUIC version {actual_version} is not supported by surge",
                    field="version",
                    suggestion=f"Supported versions: {', '.join((str(v) for v in sorted(supported_versions)))}",
                )
            )
    if node.dialer_proxy and node.ports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="TUIC port hopping cannot be combined with underlying-proxy",
                field="ports",
            )
        )
    return warnings


def emit_tuic(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, TUICNode)
    if node.version == 5:
        parts = ["tuic-v5", _server_str(node), str(node.port)]
        if node.password:
            parts.append(f"password={node.password}")
        if node.uuid:
            parts.append(f"uuid={node.uuid}")
    else:
        parts = ["tuic", _server_str(node), str(node.port)]
        if node.token:
            parts.append(f"token={node.token}")
        if node.version:
            parts.append(f"version={node.version}")
    if node.ports:
        parts.append(f"port-hopping={node.ports}")
    if node.hop_interval is not None:
        parts.append(f"port-hopping-interval={node.hop_interval}")
    return parts


CODECS = (
    _spec(
        "tuic",
        protocol=Protocol.TUIC,
        check=check_tuic,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_tuic,
        emitter=emit_tuic,
        consumed=("token", "version", "port-hopping", "port-hopping-interval"),
        constraints={"versions": {4, 5}},
    ),
    _spec(
        "tuic-v5",
        protocol=Protocol.TUIC,
        check=check_tuic,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_tuic,
        emitter=emit_tuic,
        consumed=("uuid", "password", "port-hopping", "port-hopping-interval"),
        constraints={"versions": {4, 5}},
    ),
)
