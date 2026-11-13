"""Bind sing-box node contracts without changing document tag ownership."""

from subio_v2.adapters.checks import (
    foreign_surge_options,
    ignored_fields,
    network_features,
    unsupported_grpc_parameters,
)
from subio_v2.adapters.contracts import NodeTargetCodec, TargetAdapter
from subio_v2.adapters.singbox.endpoint import SINGBOX_ENDPOINT_CODECS
from subio_v2.adapters.singbox.outbound import SINGBOX_OUTBOUND_CODECS
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node


def make_target(policy) -> TargetAdapter:
    def bind(codec, section):
        return NodeTargetCodec(
            codec.protocol,
            codec.check,
            lambda node, _: codec.encode(node),
            codec.target_constraints,
            section=section,
            precheck=lambda node: unsupported_grpc_parameters(node, "sing-box"),
            check_common=common,
        )

    def common(node: Node):
        fields = foreign_surge_options(node)
        if node.users:
            fields.append("users")
        return ignored_fields(fields, "sing-box") + network_features(
            node, policy, "sing-box"
        )

    return TargetAdapter(
        DialectContext("sing-box", "json"),
        {
            **{
                protocol: bind(codec, "outbounds")
                for protocol, codec in SINGBOX_OUTBOUND_CODECS.items()
            },
            **{
                protocol: bind(codec, "endpoints")
                for protocol, codec in SINGBOX_ENDPOINT_CODECS.items()
            },
        },
        "tests/fixtures/singbox: v1.14.3 provenance; docs/support_matrix.md: implemented codecs",
        precheck=lambda node: unsupported_grpc_parameters(node, "sing-box"),
    )
