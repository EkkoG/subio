from __future__ import annotations

from subio_v2.core.nodes import Network, Node, Protocol, TrojanNode
from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
    transport_group,
)
from subio_v2.protocols.spec import ProtocolSpec
from subio_v2.protocols.values import (
    TRANSPORT_GRPC,
    TRANSPORT_H2,
    TRANSPORT_TCP,
    TRANSPORT_WS,
)

SPEC = ProtocolSpec(
    protocol=Protocol.TROJAN,
    node_class=TrojanNode,
    user_override_fields=frozenset({"server", "port", "password"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "password"}),
    terminal_native_fields=frozenset({"password", "smux", "tls", "transport"}),
)


class TrojanCodec(StructuredClashProtocolCodec):
    spec = SPEC

    def normalize_stash(self, data: dict[str, object]) -> dict[str, object]:
        data.setdefault("tls", True)
        return data
    protocol = Protocol.TROJAN
    clash_dialects = frozenset({"mihomo", "clash", "stash"})
    clash_type = "trojan"
    dialect_fields = {
        "stash": stash_fields("password", tls=True, transport=True)
    }
    target_constraints = {
        "clash": {"transports": {TRANSPORT_TCP, TRANSPORT_WS}},
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


CODEC = TrojanCodec()
