from __future__ import annotations

from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior,
    _spec,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    TailscaleNode,
)
from subio_v2.core.results import IssueDraft, IssueSeverity


def check_tailscale(node: Node, proto_caps: dict) -> list[IssueDraft]:
    if not isinstance(node, TailscaleNode):
        return []
    warnings: list[IssueDraft] = []
    if node.exit_node_auto_fallback:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Stash automatic exit-node fallback has no equivalent Surge selection semantics",
                field="exit_node_auto_fallback",
                code="conversion.unsupported-protocol-variant",
            )
        )
    interactive_reference = bool(
        node.source_extensions.get("surge", {}).get("interactive_state_reference")
    )
    if not node.auth_key and (not (node.interactive_login and interactive_reference)):
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Surge Tailscale output requires an auth-key or an existing Surge interactive-login state reference",
                field="auth_key",
            )
        )
    if node.interface_name:
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Surge Tailscale does not support interface binding",
                field="interface_name",
            )
        )
    if node.exit_node == "auto:any":
        warnings.append(
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message="Mihomo exit-node 'auto:any' has no equivalent Surge selection semantics",
                field="exit_node",
                code="conversion.unsupported-protocol-variant",
            )
        )
    for field, value in (
        ("state_dir", node.state_dir),
        ("ephemeral", node.ephemeral),
        ("accept_routes", node.accept_routes),
        ("exit_node_allow_lan_access", node.exit_node_allow_lan_access),
        ("routing_mark", node.routing_mark),
    ):
        if value:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.WARNING,
                    message=f"Tailscale field '{field}' is Mihomo-only",
                    field=field,
                    code="conversion.unconsumed-source-field",
                )
            )
    return warnings


def emit_tailscale(node: Node, _: dict[int, str]) -> list[str]:
    assert isinstance(node, TailscaleNode)
    extension = node.source_extensions.get("surge", {})
    return ["tailscale", f"section-name={extension.get('section_name') or node.name}"]


CODECS = (
    _spec(
        "tailscale",
        protocol=Protocol.TAILSCALE,
        check=check_tailscale,
        udp=SurgeUdpBehavior.AUTOMATIC,
        emitter=emit_tailscale,
        consumed=("section-name",),
    ),
)
