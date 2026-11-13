from __future__ import annotations

from subio_v2.core.nodes import (
    MieruNode,
    Node,
    Protocol,
)
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec


def _validate(node: Node) -> list[NodeValidationError]:
    errors: list[NodeValidationError] = []
    if not isinstance(node, MieruNode):
        return errors
    if not isinstance(node.server, str) or not node.server:
        errors.append(NodeValidationError("server", "Server is required"))

    has_port = node.port is not None
    has_port_range = node.port_range not in {None, ""}
    if has_port == has_port_range:
        errors.append(
            NodeValidationError(
                "port_range", "Mieru requires exactly one of port or port-range"
            )
        )
        return errors

    if has_port and (
        not isinstance(node.port, int)
        or isinstance(node.port, bool)
        or not 1 <= node.port <= 65535
    ):
        errors.append(
            NodeValidationError(
                "port", f"Port must be between 1 and 65535, got {node.port!r}"
            )
        )
    if has_port_range and not _valid_port_range(node.port_range):
        errors.append(
            NodeValidationError(
                "port_range", f"Invalid Mieru port range: {node.port_range!r}"
            )
        )
    return errors


def _valid_port_range(value: str | None) -> bool:
    if value is None:
        return False
    parts = value.split("-", 1)
    if not all(part.isdigit() for part in parts):
        return False
    start = int(parts[0])
    end = int(parts[-1])
    return 1 <= start <= end <= 65535


SPEC = ProtocolSpec(
    protocol=Protocol.MIERU,
    required_fields=("transport", "username", "password"),
    validator=_validate,
    node_class=MieruNode,
    requires_endpoint=False,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset(
        {
            "handshake_mode",
            "multiplexing",
            "password",
            "port_range",
            "smux",
            "traffic_pattern",
            "transport",
            "username",
        }
    ),
)
