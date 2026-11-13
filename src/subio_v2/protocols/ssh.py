from __future__ import annotations

from subio_v2.core.nodes import Node, Protocol, SSHNode
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec


def _validate(node: Node) -> list[NodeValidationError]:
    errors: list[NodeValidationError] = []
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


SPEC = ProtocolSpec(
    protocol=Protocol.SSH,
    required_fields=("username",),
    validator=_validate,
    node_class=SSHNode,
    user_override_fields=frozenset(
        {
            "server",
            "port",
            "username",
            "password",
            "private_key",
            "private_key_passphrase",
        }
    ),
    terminal_native_user_override_fields=frozenset(
        {
            "server",
            "port",
            "username",
            "password",
            "private_key",
            "private_key_passphrase",
        }
    ),
    terminal_native_fields=frozenset(
        {
            "host_key",
            "host_key_algorithms",
            "idle_timeout",
            "password",
            "private_key",
            "private_key_passphrase",
            "server_fingerprints",
            "username",
        }
    ),
    terminal_native_excluded_fields=frozenset({"keystore_id"}),
)
