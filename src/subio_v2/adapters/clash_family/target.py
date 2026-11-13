"""Clash-family target bindings with their final dialect encoding."""

import subio_v2.protocols as protocol_registry
from subio_v2.adapters.checks import (
    foreign_surge_options,
    grpc_parameters,
    ignored_fields,
    network_features,
)
from subio_v2.adapters.clash_family.dialect import post_descriptor_emit
from subio_v2.adapters.contracts import NodeTargetCodec, TargetAdapter
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node, Protocol
from subio_v2.core.results import IssueDraft, IssueSeverity


def make_target(target: str, policy) -> TargetAdapter:
    context = DialectContext(target, "yaml")
    codec = protocol_registry.target_codec(target, Protocol.VLESS)

    def check_vless(node: Node) -> list[IssueDraft]:
        issues = grpc_parameters(node) + codec.check(node)
        for attr in ("grpc_mode", "grpc_authority"):
            if getattr(node.transport, attr) is not None:
                issues.append(
                    IssueDraft(
                        IssueSeverity.ERROR,
                        f"This gRPC field cannot be represented by {target}",
                        f"transport.{attr}",
                        code="conversion.unsupported-platform-field",
                    )
                )
        if node.tls.sni_disabled:
            issues.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    "This target cannot preserve the VLESS SNI disable setting",
                    "tls.sni_disabled",
                    code="conversion.unsupported-platform-field",
                )
            )
        return issues

    def encode(node: Node, _):
        return post_descriptor_emit(codec.emit(node, context), node, context, target)

    def common(node: Node) -> list[IssueDraft]:
        return ignored_fields(foreign_surge_options(node), target) + network_features(
            node, policy, target
        )

    return TargetAdapter(
        context,
        {
            codec.protocol: NodeTargetCodec(
                codec.protocol, check_vless, encode, codec.target_constraints
            )
        },
        common,
        "tests/fixtures/mihomo/schema/README.md: 88d5239 schema baseline and implemented codecs",
    )
