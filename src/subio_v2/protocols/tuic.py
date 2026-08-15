from __future__ import annotations

from typing import Any, Dict

from subio_v2.model.nodes import Node, Protocol, TUICNode
from subio_v2.protocols import register
from subio_v2.protocols._base import NodeValidationError, StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
)


class TUICDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.TUIC
    clash_type = "tuic"
    node_class = TUICNode
    fields = (
        scalar_field("token", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("uuid", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("password", emit_policy=EmitPolicy.TRUTHY),
        tls_group(
            consumed_keys=(
                "tls",
                "sni",
                "skip-cert-verify",
                "fingerprint",
                "client-fingerprint",
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

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, TUICNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
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
                    CapabilityWarning(
                        level=WarningLevel.ERROR,
                        message=f"TUIC version {actual_version} is not supported by {platform}",
                        field="version",
                        suggestion=(
                            f"Supported versions: {', '.join(str(v) for v in sorted(supported_versions))}"
                        ),
                    )
                )
        if node.dialer_proxy and node.ports:
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message="TUIC port hopping cannot be combined with underlying-proxy",
                    field="ports",
                )
            )
        return warnings


register(TUICDescriptor())
