from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from subio_v2.core.nodes import Node, OpenConnectNode, Protocol
from subio_v2.protocols._base import ClashProtocolCodec, NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec

_FLAVORS = frozenset({"anyconnect", "gp", "fortinet", "f5", "pulse", "nc"})
_UINT32_MAX = 4_294_967_295


def is_valid_openconnect_server(value: Any) -> bool:
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        return False
    authority = parsed.netloc
    if authority.startswith("["):
        closing_bracket = authority.rfind("]")
        port_suffix = authority[closing_bracket + 1 :]
        valid_port = not port_suffix or (
            port_suffix.startswith(":")
            and (
                not port_suffix[1:]
                or (port_suffix[1:].isascii() and port_suffix[1:].isdecimal())
            )
        )
    elif authority.count(":") <= 1:
        port = authority.rpartition(":")[2] if ":" in authority else ""
        valid_port = not port or (port.isascii() and port.isdecimal())
    else:
        valid_port = False
    return (
        parsed.scheme.lower() == "https"
        and hostname is not None
        and valid_port
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


SPEC = ProtocolSpec(
    protocol=Protocol.OPENCONNECT,
    node_class=OpenConnectNode,
    requires_endpoint=False,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_excluded_fields=frozenset(
        {"flavor", "username", "password", "auth_group", "cookie", "mtu"}
    ),
    native_public=False,
)


class OpenConnectCodec(ClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.OPENCONNECT
    clash_type = "openconnect"
    dynamic_clash_type = True
    clash_dialects = frozenset()

    def parse_clash(self, data: dict[str, Any], context=None) -> Node:
        raise ValueError("OpenConnect is not a Clash-family protocol")

    def emit_clash(self, node: Node, context=None) -> dict[str, Any]:
        raise ValueError("OpenConnect is not a Clash-family protocol")

    def validate(self, node: Node) -> list[NodeValidationError]:
        if not isinstance(node, OpenConnectNode):
            return []
        errors: list[NodeValidationError] = []
        if not is_valid_openconnect_server(node.server):
            errors.append(
                NodeValidationError(
                    "server",
                    "OpenConnect server must be an HTTPS URL without user information, query, fragment, or whitespace",
                )
            )
        if node.port is not None:
            errors.append(
                NodeValidationError(
                    "port", "OpenConnect server includes its endpoint in 'server'"
                )
            )
        if node.flavor is not None and (
            not isinstance(node.flavor, str) or node.flavor not in _FLAVORS
        ):
            errors.append(
                NodeValidationError("flavor", "Unsupported OpenConnect flavor")
            )
        for field in ("username", "password", "auth_group", "cookie"):
            value = getattr(node, field)
            if value is not None and not isinstance(value, str):
                errors.append(
                    NodeValidationError(
                        field, f"OpenConnect {field.replace('_', '-')} must be a string"
                    )
                )
        if node.mtu is not None and (
            type(node.mtu) is not int or not 0 <= node.mtu <= _UINT32_MAX
        ):
            errors.append(
                NodeValidationError(
                    "mtu", f"OpenConnect mtu must be between 0 and {_UINT32_MAX}"
                )
            )
        return errors


CODEC = OpenConnectCodec()
