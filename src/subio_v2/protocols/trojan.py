from __future__ import annotations

from subio_v2.capabilities.definitions import (
    TRANSPORT_GRPC,
    TRANSPORT_H2,
    TRANSPORT_TCP,
    TRANSPORT_WS,
)
from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Network, Node, Protocol, TrojanNode
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
    transport_group,
)


class TrojanDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.TROJAN
    clash_dialects = frozenset({"mihomo", "clash", "stash"})
    clash_type = "trojan"
    target_constraints = {
        "clash": {"transports": {TRANSPORT_TCP, TRANSPORT_WS}},
        "dae": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC}
        },
        "mihomo": {
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
            },
            "features": {"reality", "smux"},
        },
        "stash": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC}
        },
        "surge": {"transports": {TRANSPORT_TCP, TRANSPORT_WS}},
        "v2rayn": {
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
            }
        },
    }
    fields = (
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        tls_group(),
        transport_group(
            consumed_keys=(
                "network",
                "ws-opts",
                "h2-opts",
                "http-opts",
                "grpc-opts",
            )
        ),
        smux_group(),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, TrojanNode):
            return []
        warnings: list[IssueDraft] = []
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
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Transport '{network}' is not supported by {platform}",
                    field="transport.network",
                    suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}",
                )
            )
        if (
            node.smux
            and node.smux.enabled
            and "smux" not in proto_caps.get("features", set())
        ):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.WARNING,
                    message=f"SMUX is not supported by {platform}, will be ignored",
                    field="smux",
                )
            )
        if (
            node.tls
            and node.tls.reality_opts
            and "reality" not in proto_caps.get("features", set())
        ):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Reality is not supported for Trojan on {platform}",
                    field="reality",
                )
            )
        return warnings


DESCRIPTOR = TrojanDescriptor()
