from __future__ import annotations

from subio_v2.core.nodes import Node, Protocol, TUICNode
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec


def _validate(node: Node) -> list[NodeValidationError]:
    errors: list[NodeValidationError] = []
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
            errors.append(NodeValidationError("token", "TUIC v5 cannot use a v4 token"))
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


SPEC = ProtocolSpec(
    protocol=Protocol.TUIC,
    validator=_validate,
    node_class=TUICNode,
    user_override_fields=frozenset({"server", "port", "token", "uuid", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "token", "uuid", "password"}
    ),
    terminal_native_fields=frozenset(
        {"hop_interval", "password", "ports", "smux", "tls", "token", "uuid", "version"}
    ),
)
