"""Clash-family contracts own validation and final dialect encoding."""

import subio_v2.protocols as protocol_registry
from subio_v2.adapters.checks import (
    foreign_surge_options,
    ignored_fields,
    network_features,
    unsupported_grpc_parameters,
)
from subio_v2.adapters.clash_family.dialect import post_descriptor_emit
from subio_v2.adapters.clash_family.stash import post_stash_emit
from subio_v2.adapters.contracts import NodeTargetCodec, TargetAdapter
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node, Protocol
from subio_v2.core.results import IssueDraft, IssueSeverity


def make_target(target: str, policy) -> TargetAdapter:
    context = DialectContext(target, "yaml")

    def bind(codec):
        def encode(node: Node, _):
            output, dropped = post_descriptor_emit(
                codec.emit(node, context),
                node,
                context,
                policy,
                codec.target_constraints,
            )
            if target == "stash":
                output, stash_dropped = post_stash_emit(output, node)
                dropped = tuple(sorted({*dropped, *stash_dropped}))
            return output, dropped

        return NodeTargetCodec(
            codec.protocol,
            codec.protocol_codec.checker_for_target(target),
            encode,
            codec.target_constraints,
            precheck=lambda node: unsupported_grpc_parameters(node, target),
            check_common=common,
        )

    def common(node: Node) -> list[IssueDraft]:
        issues = ignored_fields(foreign_surge_options(node), target) + network_features(
            node, policy, target
        )
        if target == "stash" and node.dialer_proxy and node.interface_name:
            issues.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    "Stash dialer-proxy cannot be combined with interface-name",
                    "dialer_proxy",
                    code="conversion.unsupported-field-combination",
                )
            )
        return issues

    return TargetAdapter(
        context,
        {
            protocol: bind(codec)
            for protocol, codec in protocol_registry.target_codecs_for(target).items()
        },
        "tests/fixtures/mihomo/schema/README.md: 88d5239; docs/support_matrix.md: implemented Clash/Stash contracts",
        NodeTargetCodec(
            Protocol.SOURCE_PASSTHROUGH,
            lambda _: [],
            lambda node, emitter: (emitter._emit_source_passthrough(node), ()),
            precheck=lambda node: unsupported_grpc_parameters(node, target),
        ),
        precheck=lambda node: unsupported_grpc_parameters(node, target),
    )
