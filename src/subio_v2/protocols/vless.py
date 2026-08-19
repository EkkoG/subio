from __future__ import annotations

from subio_v2.capabilities.definitions import (
    TRANSPORT_GRPC,
    TRANSPORT_H2,
    TRANSPORT_HTTP,
    TRANSPORT_TCP,
    TRANSPORT_WS,
    TRANSPORT_XHTTP,
)
from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Network, Node, Protocol, VlessNode
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
    transport_group,
)


class VlessCodec(StructuredClashProtocolCodec):
    protocol = Protocol.VLESS
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "vless"
    target_constraints = {
        "dae": {
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
            },
            "features": {"reality"},
            "flows": {"xtls-rprx-vision"},
        },
        "mihomo": {
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
                TRANSPORT_HTTP,
                TRANSPORT_XHTTP,
            },
            "features": {"reality", "smux"},
            "flows": {"xtls-rprx-vision"},
        },
        "stash": {
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
                TRANSPORT_HTTP,
                TRANSPORT_XHTTP,
            },
            "features": {"reality"},
            "flows": {
                "xtls-rprx-origin",
                "xtls-rprx-direct",
                "xtls-rprx-splice",
                "xtls-rprx-vision",
            },
        },
        "v2rayn": {
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
                TRANSPORT_HTTP,
            },
            "features": {"reality"},
            "flows": {"xtls-rprx-vision"},
        },
    }
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

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, VlessNode):
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

        if node.flow:
            supported_flows = proto_caps.get("flows", set())
            if node.flow not in supported_flows:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
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
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Reality is not supported by {platform}",
                    field="reality",
                )
            )
        return warnings


CODEC = VlessCodec()
