from __future__ import annotations

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Node, Protocol, SSHNode
from subio_v2.protocols._base import NodeValidationError, StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import EmitPolicy, scalar_field
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.SSH,
    node_class=SSHNode,
    user_override_fields=frozenset({"server", "port", "username", "password", "private_key", "private_key_passphrase"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "username", "password", "private_key", "private_key_passphrase"}),
    terminal_native_fields=frozenset({"host_key", "host_key_algorithms", "idle_timeout", "password", "private_key", "private_key_passphrase", "server_fingerprints", "username"}),
    terminal_native_excluded_fields=frozenset({"keystore_id"}),
)


class SSHCodec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.SSH
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "ssh"
    dialect_fields = {
        "stash": stash_fields(
            "name", "type", "server", "port", "user", "password",
            "private-key", "private-key-passphrase", "dialer-proxy",
            "interface-name", endpoint=False,
        )
    }
    target_constraints = {
        target: {"auth_methods": {"password", "private_key"}}
        for target in ("mihomo", "stash")
    }
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


CODEC = SSHCodec()
