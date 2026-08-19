from __future__ import annotations

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Node, Protocol, SSHNode
from subio_v2.protocols._base import NodeValidationError, StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field


class SSHDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.SSH
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "ssh"
    fields = (
        scalar_field(
            "username", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field("password", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("private-key", "private_key", emit_policy=EmitPolicy.TRUTHY),
        scalar_field(
            "private-key-passphrase",
            "private_key_passphrase",
            emit_policy=EmitPolicy.TRUTHY,
        ),
        scalar_field("host-key", "host_key", emit_policy=EmitPolicy.TRUTHY),
        scalar_field(
            "host-key-algorithms",
            "host_key_algorithms",
            emit_policy=EmitPolicy.TRUTHY,
        ),
    )

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = super().validate(node)
        if not isinstance(node, SSHNode):
            return errors
        if not (node.password or node.private_key or node.keystore_id):
            errors.append(
                NodeValidationError(
                    "password",
                    "SSH requires password or private key authentication",
                )
            )
        return errors

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, SSHNode):
            return []
        warnings: list[IssueDraft] = []
        supported_auth = proto_caps.get("auth_methods", set())
        if node.private_key and "private_key" not in supported_auth:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"SSH private key authentication is not supported by {platform}",
                    field="private_key",
                )
            )
        if node.password and "password" not in supported_auth:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"SSH password authentication is not supported by {platform}",
                    field="password",
                )
            )
        return warnings


DESCRIPTOR = SSHDescriptor()
