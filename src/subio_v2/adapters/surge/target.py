"""Surge contracts bind validation to the actual policy emitter."""

from subio_v2.adapters.checks import (
    grpc_parameters,
    ignored_fields,
    network_features,
    unsupported_grpc_parameters,
)
from subio_v2.adapters.contracts import NodeTargetCodec, TargetAdapter
from subio_v2.adapters.surge.codecs import SURGE_PROTOCOL_CODECS
from subio_v2.adapters.surge.validation import (
    SURGE_RESERVED_POLICY_NAMES,
    validate_surge_common,
    validate_surge_parameters,
)
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node, Protocol
from subio_v2.core.results import IssueDraft, IssueSeverity


def make_target(policy) -> TargetAdapter:
    def bind(codec):
        grpc_check = (
            grpc_parameters
            if codec.protocol == Protocol.VLESS
            else lambda node: unsupported_grpc_parameters(node, "surge")
        )

        def check(node):
            return codec.check(node, codec.target_constraints)

        return NodeTargetCodec(
            codec.protocol,
            check,
            lambda node, context: context._encode_protocol(node, codec.emitter),
            codec.target_constraints,
            precheck=lambda node: validate_surge_common(node)
            + check_policy_name(node)
            + grpc_check(node)
            + codec.precheck(node),
            check_common=common,
        )

    def common(node: Node) -> list[IssueDraft]:
        issues = []
        return (
            issues
            + ignored_fields(
                ["routing_mark"] if node.routing_mark is not None else [], "surge"
            )
            + network_features(node, policy, "surge")
        )

    return TargetAdapter(
        DialectContext("surge", "text"),
        {protocol: bind(codec) for protocol, codec in SURGE_PROTOCOL_CODECS.items()},
        "tests/fixtures/surge/official/README.md; docs/support_matrix.md#13-surge-vless",
        NodeTargetCodec(
            Protocol.SOURCE_PASSTHROUGH,
            lambda node: [],
            lambda node, context: context._encode_protocol(node),
            precheck=lambda node: validate_surge_common(node)
            + check_policy_name(node)
            + check_source_passthrough(node),
        ),
        precheck=lambda node: validate_surge_common(node) + check_policy_name(node),
    )


def check_policy_name(node: Node) -> list[IssueDraft]:
    if isinstance(node.name, str) and node.name.upper() in SURGE_RESERVED_POLICY_NAMES:
        return [
            IssueDraft(
                IssueSeverity.ERROR,
                f"Surge built-in policy name '{node.name}' cannot be used for a node",
                "name",
                code="conversion.reserved-policy-name",
            )
        ]
    return []


def check_source_passthrough(node: Node) -> list[IssueDraft]:
    from collections.abc import Mapping

    parameters = getattr(getattr(node.raw, "parameters", None), "last_values", None)
    if not isinstance(parameters, Mapping):
        return []
    try:
        validate_surge_parameters(parameters, node.original_type or "external")
    except (TypeError, ValueError) as exc:
        return [
            IssueDraft(
                IssueSeverity.ERROR,
                f"Invalid Surge policy parameter: {exc}",
                "parameters",
                code="conversion.invalid-value",
            )
        ]
    return []
