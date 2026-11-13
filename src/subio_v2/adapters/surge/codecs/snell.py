from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.adapters.surge.codecs._shared import (
    SurgeProtocolParseContext,
    _server_str,
)
from subio_v2.adapters.surge.validation import (
    SURGE_SNELL_MODES,
    SURGE_SNELL_VERSIONS,
    _error,
    _validate_node_obfs_uri,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    SnellNode,
    TLSSettings,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def parse_snell(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    try:
        version = int(values["version"]) if values.get("version") else None
    except (TypeError, ValueError):
        version = None
    return SnellNode(
        name=context.record.name,
        type=Protocol.SNELL,
        server=context.server,
        port=context.port,
        psk=values.get("psk", ""),
        version=version,
        reuse=(context.get_bool("reuse") if values.get("reuse") is not None else None),
        udp_port=context.get_int("udp-port"),
        mode=values.get("mode"),
        obfs=values.get("obfs"),
        obfs_host=values.get("obfs-host"),
        obfs_uri=values.get("obfs-uri"),
        tls=TLSSettings(enabled=False),
        udp=bool(version and version >= 3),
    )


def check_snell(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, SnellNode):
        return []
    warnings: list[IssueDraft] = []
    version = node.version or 1
    if node.version:
        supported_versions = proto_caps.get("versions", set())
        if supported_versions and node.version not in supported_versions:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Snell version {node.version} is not supported by surge",
                    field="version",
                    suggestion=f"Supported versions: {', '.join((str(v) for v in sorted(supported_versions)))}",
                )
            )
    if node.obfs:
        by_version = proto_caps.get("obfs_modes_by_version", {})
        supported_obfs = by_version.get(version, proto_caps.get("obfs_modes", set()))
        if supported_obfs and node.obfs not in supported_obfs:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Obfs mode '{node.obfs}' is not supported by surge",
                    field="obfs",
                )
            )
        elif by_version and (not supported_obfs):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Snell version {version} does not support obfs on surge",
                    field="obfs",
                )
            )
    if node.reuse is not None:
        reuse_versions = proto_caps.get("reuse_versions", set())
        if reuse_versions and version not in reuse_versions:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Snell version {version} does not support reuse on surge",
                    field="reuse",
                )
            )
    if node.udp_port is not None and version < 3:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Snell version {version} does not support udp-port",
                field="udp_port",
            )
        )
    if node.mode and version != 6:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Snell mode is only supported by version 6",
                field="mode",
            )
        )
    return warnings


def emit_snell(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, SnellNode)
    parts = ["snell", _server_str(node), str(node.port), f"psk={node.psk}"]
    if node.version:
        parts.append(f"version={node.version}")
    if node.reuse is not None:
        parts.append(f"reuse={str(node.reuse).lower()}")
    if node.udp_port is not None:
        parts.append(f"udp-port={node.udp_port}")
    if node.mode:
        parts.append(f"mode={node.mode}")
    if node.obfs:
        parts.append(f"obfs={node.obfs}")
    if node.obfs_host:
        parts.append(f"obfs-host={node.obfs_host}")
    if node.obfs_uri:
        parts.append(f"obfs-uri={node.obfs_uri}")
    return parts


def validate_snell_fields(node: SnellNode) -> list[IssueDraft]:
    errors: list[IssueDraft] = []
    version = node.version or 1
    if node.version is not None and node.version not in SURGE_SNELL_VERSIONS:
        errors.append(_error("Snell version must be between 1 and 6", "version"))
    if node.reuse is not None and version not in {4, 5, 6}:
        errors.append(
            _error(f"Snell version {version} does not support reuse", "reuse")
        )
    if node.udp_port is not None:
        if (
            not isinstance(node.udp_port, int)
            or isinstance(node.udp_port, bool)
            or not 1 <= node.udp_port <= 65535
        ):
            errors.append(_error("udp_port must be between 1 and 65535", "udp_port"))
        elif version < 3:
            errors.append(
                _error(f"Snell version {version} does not support udp-port", "udp_port")
            )
    if node.mode is not None:
        if version != 6:
            errors.append(_error("Snell mode is only supported by version 6", "mode"))
        elif node.mode not in SURGE_SNELL_MODES:
            errors.append(
                _error(
                    "Snell mode must be one of " + ", ".join(sorted(SURGE_SNELL_MODES)),
                    "mode",
                )
            )
    _validate_node_obfs_uri(node.obfs_uri, node.obfs, errors)
    return errors


CODECS = (
    _spec(
        "snell",
        protocol=Protocol.SNELL,
        precheck=validate_snell_fields,
        check=check_snell,
        udp=SurgeUdpBehavior.VERSIONED,
        parser=parse_snell,
        emitter=emit_snell,
        consumed=(
            "psk",
            "version",
            "reuse",
            "udp-port",
            "mode",
            "obfs",
            "obfs-host",
            "obfs-uri",
        ),
        constraints={
            "obfs_modes": {"http", "tls"},
            "obfs_modes_by_version": {
                1: {"http", "tls"},
                2: {"http", "tls"},
                3: {"http", "tls"},
                4: {"http"},
                5: {"http"},
                6: set(),
            },
            "reuse_versions": {4, 5, 6},
            "versions": {1, 2, 3, 4, 5, 6},
        },
    ),
)
