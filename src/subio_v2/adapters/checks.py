"""Shared checks composed by concrete target contracts."""

from subio_v2.core.nodes import Node, SurgePolicyOptions
from subio_v2.core.results import IssueDraft, IssueSeverity


def grpc_parameters(node: Node) -> list[IssueDraft]:
    transport = getattr(node, "transport", None)
    issues = []
    for attr in ("grpc_mode", "grpc_authority"):
        value = getattr(transport, attr, None)
        if value is None:
            continue
        field = f"transport.{attr}"
        if transport.network_value != "grpc":
            issues.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    "gRPC parameters require the gRPC transport",
                    field,
                )
            )
        elif not isinstance(value, str) or (
            attr == "grpc_mode" and value not in {"gun", "multi"}
        ):
            issues.append(
                IssueDraft(IssueSeverity.ERROR, "Invalid gRPC parameter", field)
            )
    return issues


def network_features(node: Node, policy, target: str) -> list[IssueDraft]:
    return [
        IssueDraft(
            IssueSeverity.INFO,
            f"{label} is not supported by {target}, will be ignored",
            attr,
        )
        for attr, label in (
            ("tfo", "TFO"),
            ("mptcp", "MPTCP"),
            ("dialer_proxy", "Dialer proxy"),
        )
        if getattr(node, attr) and not getattr(policy, attr)
    ]


def foreign_surge_options(node: Node) -> list[str]:
    fields = []
    if node.surge_options != SurgePolicyOptions():
        fields.append("surge_options")
    if node.shadow_tls.enabled:
        fields.append("shadow_tls")
    return fields


def ignored_fields(fields: list[str], target: str) -> list[IssueDraft]:
    if not fields:
        return []
    names = ", ".join(sorted(fields))
    return [
        IssueDraft(
            IssueSeverity.WARNING,
            f"Node fields cannot be represented by {target}: {names}",
            names,
            code="conversion.unsupported-platform-field",
        )
    ]
