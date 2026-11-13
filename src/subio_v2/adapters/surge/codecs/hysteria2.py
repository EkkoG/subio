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
    Hysteria2Node,
    Node,
    Protocol,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_hysteria2(context: SurgeProtocolParseContext) -> Node | None:
    values = context.values
    salamander_password = values.get("salamander-password")
    gecko_password = values.get("gecko-password")
    if salamander_password and gecko_password:
        return None
    if salamander_password:
        obfs, obfs_password = "salamander", salamander_password
    elif gecko_password:
        obfs, obfs_password = "gecko", gecko_password
    else:
        obfs = values.get("obfs")
        obfs_password = values.get("obfs-password")
    return Hysteria2Node(
        name=context.record.name,
        type=Protocol.HYSTERIA2,
        server=context.server,
        port=context.port,
        password=values.get("password", ""),
        up=values.get("upload-bandwidth") or values.get("up"),
        down=values.get("download-bandwidth") or values.get("down"),
        ports=values.get("port-hopping"),
        hop_interval=context.get_int("port-hopping-interval"),
        obfs=obfs,
        obfs_password=obfs_password,
        tls=context.build_tls(enabled=True),
        udp=True,
    )


def check_hysteria2(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, Hysteria2Node):
        return []
    warnings: list[IssueDraft] = []
    if node.obfs and "obfs" not in proto_caps.get("features", set()):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Obfs is not supported for Hysteria2 on surge",
                field="obfs",
            )
        )
    elif node.obfs:
        supported_modes = proto_caps.get("obfs_modes", set())
        if supported_modes and node.obfs not in supported_modes:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Hysteria2 obfs mode '{node.obfs}' is not supported by surge",
                    field="obfs",
                )
            )
        if not node.obfs_password:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="Hysteria2 obfs requires a password",
                    field="obfs_password",
                )
            )
    if node.dialer_proxy and node.ports:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Hysteria2 port hopping cannot be combined with underlying-proxy",
                field="ports",
            )
        )
    return warnings


def emit_hysteria2(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, Hysteria2Node)
    parts = ["hysteria2", _server_str(node), str(node.port)]
    if node.password:
        parts.append(f"password={node.password}")
    if node.down:
        parts.append(f"download-bandwidth={node.down}")
    if node.up:
        parts.append(f"upload-bandwidth={node.up}")
    if node.obfs == "salamander" and node.obfs_password:
        parts.append(f"salamander-password={node.obfs_password}")
    elif node.obfs == "gecko" and node.obfs_password:
        parts.append(f"gecko-password={node.obfs_password}")
    if node.ports:
        parts.append(f"port-hopping={node.ports}")
    if node.hop_interval is not None:
        parts.append(f"port-hopping-interval={node.hop_interval}")
    return parts


CODECS = (
    _spec(
        "hysteria2",
        protocol=Protocol.HYSTERIA2,
        check=check_hysteria2,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_hysteria2,
        emitter=emit_hysteria2,
        consumed=(
            "password",
            "download-bandwidth",
            "upload-bandwidth",
            "up",
            "down",
            "salamander-password",
            "gecko-password",
            "obfs",
            "obfs-password",
            "port-hopping",
            "port-hopping-interval",
        ),
        emitted=(
            "password",
            "download-bandwidth",
            "upload-bandwidth",
            "salamander-password",
            "gecko-password",
            "port-hopping",
            "port-hopping-interval",
        ),
        normalized=(
            ("up", "upload-bandwidth"),
            ("down", "download-bandwidth"),
            ("obfs", "salamander-password/gecko-password"),
            ("obfs-password", "salamander-password/gecko-password"),
        ),
        constraints={"features": {"obfs"}, "obfs_modes": {"salamander", "gecko"}},
    ),
)
