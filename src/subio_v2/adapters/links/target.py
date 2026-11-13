"""Link target contracts; URI limitations belong with link encoding."""

from subio_v2.adapters.checks import (
    foreign_surge_options,
    grpc_parameters,
    ignored_fields,
    network_features,
)
from subio_v2.adapters.contracts import NodeTargetCodec, TargetAdapter
from subio_v2.adapters.links.codecs import get_codec
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
    codec = get_codec(Protocol.VLESS)
    constraints = codec.target_constraints[target]

    def check_vless(node: Node) -> list[IssueDraft]:
        issues = grpc_parameters(node)
        network = node.transport.network_value
        transports = constraints["transports"]
        if network not in transports:
            issues.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    f"Transport '{network}' is not supported by {target}",
                    "transport.network",
                    suggestion=f"Supported transports: {', '.join(sorted(transports))}",
                )
            )
        flows = constraints.get("flows", set())
        if node.flow and node.flow not in flows:
            issues.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    f"Flow '{node.flow}' is not supported by {target}",
                    "flow",
                    suggestion=f"Supported flows: {', '.join(sorted(flows))}"
                    if flows
                    else "No flows supported",
                )
            )
        if node.tls.reality_opts and "reality" not in constraints.get(
            "features", set()
        ):
            issues.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    f"Reality is not supported by {target}",
                    "reality",
                )
            )
        return issues

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
            codec.protocol: NodeTargetCodec(
                codec.protocol,
                check_vless,
                lambda node, _: codec.build(node),
                constraints,
            )
        },
        common,
        "docs/support_matrix.md#13-surge-vless: implemented VLESS share-link contract",
    )
