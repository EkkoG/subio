"""Surge contracts bind validation to the actual policy emitter."""

from subio_v2.adapters.checks import grpc_parameters, ignored_fields, network_features
from subio_v2.adapters.contracts import NodeTargetCodec, TargetAdapter
from subio_v2.adapters.surge.codecs import get_surge_protocol_codec
from subio_v2.adapters.surge.validation import (
    SURGE_RESERVED_POLICY_NAMES,
    validate_surge_node,
)
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node, Protocol
from subio_v2.core.results import IssueDraft, IssueSeverity


def make_target(policy) -> TargetAdapter:
    codec = get_surge_protocol_codec(Protocol.VLESS)

    def check_vless(node: Node) -> list[IssueDraft]:
        return grpc_parameters(node) + validate_surge_node(node)

    def encode(node: Node, context):
        return context._encode_protocol(node, codec.emitter)

    def common(node: Node) -> list[IssueDraft]:
        issues = []
        if (
            isinstance(node.name, str)
            and node.name.upper() in SURGE_RESERVED_POLICY_NAMES
        ):
            issues.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    f"Surge built-in policy name '{node.name}' cannot be used for a node",
                    "name",
                    code="conversion.reserved-policy-name",
                )
            )
        return (
            issues
            + ignored_fields(
                ["routing_mark"] if node.routing_mark is not None else [], "surge"
            )
            + network_features(node, policy, "surge")
        )

    return TargetAdapter(
        DialectContext("surge", "text"),
        {
            codec.protocol: NodeTargetCodec(
                codec.protocol, check_vless, encode, codec.target_constraints
            )
        },
        common,
        "tests/fixtures/surge/official/README.md; docs/support_matrix.md#13-surge-vless",
    )
