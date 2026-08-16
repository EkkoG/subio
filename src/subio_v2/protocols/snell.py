from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Node, Protocol, SnellNode
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    field_group,
    scalar_field,
    smux_group,
)


def _parse_obfs_opts(data: Mapping[str, Any]) -> dict[str, Any]:
    value = data.get("obfs-opts")
    if not isinstance(value, dict):
        return {"obfs": None, "obfs_host": None, "obfs_opts": value}
    return {
        "obfs": value.get("mode"),
        "obfs_host": value.get("host"),
        "obfs_opts": value,
    }


def _emit_obfs_opts(out: MutableMapping[str, Any], node: Node) -> None:
    assert isinstance(node, SnellNode)
    if node.obfs_opts:
        out["obfs-opts"] = node.obfs_opts
    elif node.obfs:
        out["obfs-opts"] = {
            "mode": node.obfs,
            "host": node.obfs_host or "bing.com",
        }


class SnellDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.SNELL
    clash_type = "snell"
    node_class = SnellNode
    fields = (
        scalar_field("psk", default="", emit_policy=EmitPolicy.ALWAYS, required=True),
        scalar_field("version", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("reuse", emit_policy=EmitPolicy.NOT_NONE),
        field_group(
            consumed_keys=("obfs-opts",),
            node_attrs=("obfs", "obfs_host", "obfs_opts"),
            parse_kwargs=_parse_obfs_opts,
            emit_into=_emit_obfs_opts,
        ),
        smux_group(),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
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
                        message=f"Snell version {node.version} is not supported by {platform}",
                        field="version",
                        suggestion=(
                            f"Supported versions: {', '.join(str(v) for v in sorted(supported_versions))}"
                        ),
                    )
                )
        if node.obfs:
            by_version = proto_caps.get("obfs_modes_by_version", {})
            supported_obfs = by_version.get(
                version, proto_caps.get("obfs_modes", set())
            )
            if supported_obfs and node.obfs not in supported_obfs:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=f"Obfs mode '{node.obfs}' is not supported by {platform}",
                        field="obfs",
                    )
                )
            elif by_version and not supported_obfs:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            f"Snell version {version} does not support obfs on {platform}"
                        ),
                        field="obfs",
                    )
                )
        if node.reuse is not None:
            reuse_versions = proto_caps.get("reuse_versions", set())
            if reuse_versions and version not in reuse_versions:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            f"Snell version {version} does not support reuse on {platform}"
                        ),
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
        if node.udp_port is not None and platform != "surge":
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Snell udp-port cannot be represented by {platform}",
                    field="udp_port",
                    code="conversion.unconsumed-source-field",
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


register(SnellDescriptor())
