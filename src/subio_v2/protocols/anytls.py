from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import AnyTLSNode, Node, Protocol
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._fields import (
    EmitPolicy,
    field_group,
    scalar_field,
    tls_group,
)


def _parse_reuse(data: Mapping[str, Any]) -> dict[str, Any]:
    return {"reuse": not bool(data.get("disable-reuse", False))}


def _emit_reuse(out: MutableMapping[str, Any], node: Node) -> None:
    assert isinstance(node, AnyTLSNode)
    if not node.reuse:
        out["disable-reuse"] = True


class AnyTLSCodec(StructuredClashProtocolCodec):
    protocol = Protocol.ANYTLS
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "anytls"
    fields = (
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        tls_group(
            consumed_keys=(
                "sni",
                "skip-cert-verify",
                "fingerprint",
                "client-fingerprint",
                "name-cert-verify",
                "alpn",
                "certificate",
                "private-key",
            ),
            force_enabled=True,
        ),
        scalar_field(
            "idle-session-check-interval",
            "idle_session_check_interval",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "idle-session-timeout",
            "idle_session_timeout",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "min-idle-session",
            "min_idle_session",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        field_group(
            consumed_keys=("disable-reuse",),
            node_attrs=("reuse",),
            parse_kwargs=_parse_reuse,
            emit_into=_emit_reuse,
        ),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if (
            not isinstance(node, AnyTLSNode)
            or node.reuse
            or platform in {"mihomo", "surge"}
        ):
            return []
        return [
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"AnyTLS reuse=false cannot be represented by {platform}",
                field="reuse",
            )
        ]


CODEC = AnyTLSCodec()
