from __future__ import annotations

from typing import Any, Dict

from subio_v2.clash.helpers import (
    assign_extra,
    emit_base,
    emit_smux,
    merge_extra,
    parse_base_fields,
    parse_smux,
)
from subio_v2.model.nodes import Node, Protocol, SnellNode
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class SnellDescriptor(ProtocolDescriptor):
    protocol = Protocol.SNELL
    clash_type = "snell"
    node_class = SnellNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        obfs_opts = data.get("obfs-opts")
        obfs = None
        obfs_host = None
        if isinstance(obfs_opts, dict):
            obfs = obfs_opts.get("mode")
            obfs_host = obfs_opts.get("host")
        handled = {"psk", "version", "obfs-opts", "smux"}
        node = SnellNode(
            type=Protocol.SNELL,
            psk=data.get("psk", ""),
            version=data.get("version"),
            obfs=obfs,
            obfs_host=obfs_host,
            obfs_opts=obfs_opts,
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, SnellNode):
            raise TypeError(f"Expected SnellNode, got {type(node)}")
        base = emit_base(node)
        base["psk"] = node.psk
        if node.version is not None:
            base["version"] = node.version
        if node.obfs_opts:
            base["obfs-opts"] = node.obfs_opts
        elif node.obfs:
            base["obfs-opts"] = {"mode": node.obfs, "host": node.obfs_host or "bing.com"}
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, SnellNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        if node.version:
            supported_versions = proto_caps.get("versions", set())
            if supported_versions and node.version not in supported_versions:
                warnings.append(
                    CapabilityWarning(
                        level=WarningLevel.ERROR,
                        message=f"Snell version {node.version} is not supported by {platform}",
                        field="version",
                        suggestion=(
                            f"Supported versions: {', '.join(str(v) for v in sorted(supported_versions))}"
                        ),
                    )
                )
        if node.obfs:
            supported_obfs = proto_caps.get("obfs_modes", set())
            if supported_obfs and node.obfs not in supported_obfs:
                warnings.append(
                    CapabilityWarning(
                        level=WarningLevel.WARNING,
                        message=f"Obfs mode '{node.obfs}' may not be supported",
                        field="obfs",
                    )
                )
        return warnings


register(SnellDescriptor())
