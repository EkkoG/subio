"""Link target contracts; URI limitations belong with link encoding."""

from subio_v2.adapters.checks import (
    foreign_surge_options,
    grpc_parameters,
    ignored_fields,
    network_features,
    unsupported_grpc_parameters,
)
from subio_v2.adapters.contracts import NodeTargetCodec, TargetAdapter
from subio_v2.adapters.links.codecs import all_codecs
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node, Protocol
from subio_v2.core.results import IssueDraft, IssueSeverity


def check_link_fields(node: Node) -> list[IssueDraft]:
    issues = []
    transport = getattr(node, "transport", None)
    headers = getattr(transport, "headers", None)
    if headers and (
        transport.network_value not in {"ws", "http"}
        or set(headers) != {"Host"}
        or not isinstance(headers["Host"], str)
    ):
        issues.append(
            IssueDraft(
                IssueSeverity.ERROR,
                "Links can only preserve a single string Host header for WS/HTTP transport",
                "transport.headers",
                code="conversion.unsupported-platform-field",
            )
        )
    tls = getattr(node, "tls", None)
    for attr in (
        "verify_name",
        "certificate_sha256",
        "client_cert_ref",
        "certificate",
        "private_key",
        "ech_opts",
        "sni_disabled",
    ):
        if getattr(tls, attr, None):
            issues.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    "Links cannot preserve this TLS setting",
                    f"tls.{attr}",
                    code="conversion.unsupported-platform-field",
                )
            )
    return issues


def make_target(target: str, policy) -> TargetAdapter:
    def bind(codec):
        constraints = codec.target_constraints.get(target, {})
        grpc_check = (
            grpc_parameters
            if codec.protocol == Protocol.VLESS
            else lambda node: unsupported_grpc_parameters(node, target)
        )

        def check(node):
            return codec.check(node, constraints, target)

        return NodeTargetCodec(
            codec.protocol,
            check,
            lambda node, _: codec.build(node),
            constraints,
            precheck=grpc_check,
            check_common=common,
        )

    def common(node: Node) -> list[IssueDraft]:
        fields = foreign_surge_options(node)
        if node.interface_name:
            fields.append("interface_name")
        if node.users:
            fields.append("users")
        if node.routing_mark is not None:
            fields.append("routing_mark")
        return (
            check_link_fields(node)
            + ignored_fields(fields, target)
            + network_features(node, policy, target)
        )

    return TargetAdapter(
        DialectContext(target, "text"),
        {
            codec.protocol: bind(codec)
            for codec in all_codecs()
            if target in codec.targets
        },
        "docs/support_matrix.md#13-surge-vless: implemented share-link contracts",
    )
