from __future__ import annotations

from typing import Any

from subio_v2.model.nodes import Network, Node, Protocol, VlessNode
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
    transport_group,
)


class VlessDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.VLESS
    clash_type = "vless"
    node_class = VlessNode
    fields = (
        scalar_field("uuid", default="", emit_policy=EmitPolicy.ALWAYS, required=True),
        scalar_field("flow", emit_policy=EmitPolicy.TRUTHY),
        scalar_field(
            "packet-encoding", "packet_encoding", emit_policy=EmitPolicy.TRUTHY
        ),
        tls_group(),
        transport_group(),
        smux_group(),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, VlessNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        supported_transports = proto_caps.get("transports", set())
        network = node.transport.network_value if node.transport else "tcp"
        unknown_network = node.transport and not isinstance(
            node.transport.network, Network
        )
        if (
            supported_transports
            and network not in supported_transports
            and not (platform == "mihomo" and unknown_network)
        ):
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"Transport '{network}' is not supported by {platform}",
                    field="transport.network",
                    suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}",
                )
            )

        if node.flow:
            supported_flows = proto_caps.get("flows", set())
            if node.flow not in supported_flows:
                warnings.append(
                    CapabilityWarning(
                        level=WarningLevel.ERROR,
                        message=f"Flow '{node.flow}' is not supported by {platform}",
                        field="flow",
                        suggestion=(
                            f"Supported flows: {', '.join(sorted(supported_flows))}"
                            if supported_flows
                            else "No flows supported"
                        ),
                    )
                )

        if (
            node.tls
            and node.tls.reality_opts
            and "reality" not in proto_caps.get("features", set())
        ):
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"Reality is not supported by {platform}",
                    field="reality",
                )
            )
        return warnings


register(VlessDescriptor())
