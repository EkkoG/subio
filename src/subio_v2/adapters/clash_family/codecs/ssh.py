from __future__ import annotations

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._dialects import stash_fields
from subio_v2.adapters.clash_family.codecs._fields import EmitPolicy, scalar_field
from subio_v2.core.nodes import Node, Protocol, SSHNode
from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.protocols.ssh import SPEC


class SSHCodec(StructuredClashProtocolCodec):
    spec = SPEC
    stash_input_aliases = {"user": "username"}
    stash_output_aliases = {"username": "user"}

    def stash_lossless_default(self, node: Node, key: str, value: object) -> bool:
        return key == "udp" and node.udp

    protocol = Protocol.SSH
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "ssh"
    dialect_fields = {
        "stash": stash_fields(
            "name",
            "type",
            "server",
            "port",
            "user",
            "password",
            "private-key",
            "private-key-passphrase",
            "dialer-proxy",
            "interface-name",
            endpoint=False,
        )
    }
    target_constraints = {
        target: {"auth_methods": {"password", "private_key"}}
        for target in ("mihomo", "stash")
    }
    fields = (
        scalar_field("username", default="", emit_policy=EmitPolicy.ALWAYS),
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

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, SSHNode):
            return []
        warnings: list[IssueDraft] = []
        if node.server_fingerprints:
            warnings.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    "This target cannot preserve SSH server fingerprints",
                    "server_fingerprints",
                    code="conversion.unsupported-platform-field",
                )
            )
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
