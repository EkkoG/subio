from __future__ import annotations

from typing import Any, Dict

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Node, Protocol, TUICNode
from subio_v2.protocols._base import NodeValidationError, StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
)
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.TUIC,
    node_class=TUICNode,
    user_override_fields=frozenset({"server", "port", "token", "uuid", "password"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "token", "uuid", "password"}),
    terminal_native_fields=frozenset({"hop_interval", "password", "ports", "smux", "tls", "token", "uuid", "version"}),
)


class TUICCodec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.TUIC
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "tuic"
    dialect_fields = {
        "stash": stash_fields(
            "version",
            "uuid",
            "password",
            "token",
            "ports",
            "hop-interval",
            tls=True,
        )
    }
    target_constraints = {
        "mihomo": {"versions": {4, 5}},
        "stash": {"versions": {4, 5}},
    }
    fields = (
        scalar_field("token", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("uuid", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("password", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("ports", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("hop-interval", "hop_interval", emit_policy=EmitPolicy.NOT_NONE),
        tls_group(
            consumed_keys=(
                "tls",
                "sni",
                "skip-cert-verify",
                "fingerprint",
                "client-fingerprint",
                "name-cert-verify",
                "alpn",
                "certificate",
                "private-key",
                "ech-opts",
            ),
            default_enabled=True,
        ),
        smux_group(),
    )

    def prepare_parse_kwargs(
        self, data: Dict[str, Any], kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        if data.get("uuid") or data.get("password"):
            kwargs["version"] = 5
        elif data.get("token"):
            kwargs["version"] = 4
        else:
            kwargs["version"] = None
        return kwargs

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = super().validate(node)
        if not isinstance(node, TUICNode):
            return errors
        if node.version == 4:
            if not node.token:
                errors.append(NodeValidationError("token", "TUIC v4 requires a token"))
            if node.uuid or node.password:
                errors.append(
                    NodeValidationError(
                        "uuid", "TUIC v4 cannot use v5 UUID/password credentials"
                    )
                )
            return errors
        if node.version == 5:
            if not node.uuid:
                errors.append(NodeValidationError("uuid", "TUIC v5 requires a UUID"))
            if not node.password:
                errors.append(
                    NodeValidationError("password", "TUIC v5 requires a password")
                )
            if node.token:
                errors.append(
                    NodeValidationError("token", "TUIC v5 cannot use a v4 token")
                )
            return errors
        if node.uuid or node.password:
            if not node.uuid:
                errors.append(NodeValidationError("uuid", "TUIC v5 requires a UUID"))
            if not node.password:
                errors.append(
                    NodeValidationError("password", "TUIC v5 requires a password")
                )
        elif not node.token:
            errors.append(
                NodeValidationError(
                    "token", "TUIC requires either a v4 token or v5 UUID/password"
                )
            )
        return errors

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, TUICNode):
            return []
        warnings: list[IssueDraft] = []
        actual_version = node.version
        if actual_version is None:
            if node.uuid or node.password:
                actual_version = 5
            elif node.token:
                actual_version = 4
        if actual_version:
            supported_versions = proto_caps.get("versions", set())
            if supported_versions and actual_version not in supported_versions:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=f"TUIC version {actual_version} is not supported by {platform}",
                        field="version",
                        suggestion=(
                            f"Supported versions: {', '.join(str(v) for v in sorted(supported_versions))}"
                        ),
                    )
                )
        if platform != "stash" and node.dialer_proxy and node.ports:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="TUIC port hopping cannot be combined with underlying-proxy",
                    field="ports",
                )
            )
        return warnings


CODEC = TUICCodec()
