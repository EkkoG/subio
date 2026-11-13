from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxEndpointCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _COMMON_KEYS,
    _ROUTING_MARK_MAX,
    SingBoxCodecError,
    _common_kwargs,
    _optional_enum_string,
    _optional_int,
    _optional_string,
    _required_string,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _ENDPOINT_COMMON_NODE_FIELDS as _COMMON_NODE_FIELDS,
)
from subio_v2.core.nodes import (
    Node,
    OpenConnectNode,
    Protocol,
)
from subio_v2.protocols.openconnect import is_valid_openconnect_server

_OPENCONNECT_KEYS = _COMMON_KEYS | frozenset(
    {"server", "flavor", "username", "password", "auth_group", "cookie", "mtu"}
)


_OPENCONNECT_FLAVORS = frozenset({"anyconnect", "gp", "fortinet", "f5", "pulse", "nc"})


class SingBoxOpenConnectEndpointCodec(SingBoxEndpointCodec):
    singbox_type = "openconnect"
    protocol = Protocol.OPENCONNECT
    node_class = OpenConnectNode
    allowed_keys = _OPENCONNECT_KEYS
    allowed_node_fields = _COMMON_NODE_FIELDS | frozenset(
        {"server", "flavor", "username", "password", "auth_group", "cookie", "mtu"}
    )
    expected_udp = True

    @staticmethod
    def _server(data: dict[str, Any]) -> str:
        server = _required_string(data, "server")
        if not is_valid_openconnect_server(server):
            raise SingBoxCodecError(
                "server",
                "Sing-box OpenConnect server must be an HTTPS URL without user information, query, fragment, or whitespace",
                "parse.singbox.invalid-field",
            )
        return server

    def parse(self, data: dict[str, Any]) -> OpenConnectNode:
        mtu = _optional_int(data, "mtu")
        if mtu is not None and not 0 <= mtu <= _ROUTING_MARK_MAX:
            raise SingBoxCodecError(
                "mtu",
                f"Sing-box OpenConnect mtu must be between 0 and {_ROUTING_MARK_MAX}",
                "parse.singbox.invalid-field",
            )
        kwargs = _common_kwargs(data, udp=True)
        kwargs.update(
            server=self._server(data),
            flavor=_optional_enum_string(data, "flavor", _OPENCONNECT_FLAVORS),
            username=_optional_string(data, "username"),
            password=_optional_string(data, "password"),
            auth_group=_optional_string(data, "auth_group"),
            cookie=_optional_string(data, "cookie"),
            mtu=mtu,
        )
        return OpenConnectNode(**kwargs)

    def _check_protocol(self, node: Node) -> list[str]:
        assert isinstance(node, OpenConnectNode)
        unsupported = []
        if not is_valid_openconnect_server(node.server):
            unsupported.append("server")
        if node.flavor is not None and (
            not isinstance(node.flavor, str) or node.flavor not in _OPENCONNECT_FLAVORS
        ):
            unsupported.append("flavor")
        for field in ("username", "password", "auth_group", "cookie"):
            value = getattr(node, field)
            if value is not None and not isinstance(value, str):
                unsupported.append(field)
        if node.mtu is not None and (
            type(node.mtu) is not int or not 0 <= node.mtu <= _ROUTING_MARK_MAX
        ):
            unsupported.append("mtu")
        return unsupported

    def _emit_protocol(self, out: dict[str, Any], node: Node) -> None:
        assert isinstance(node, OpenConnectNode)
        out["server"] = node.server
        for field in ("flavor", "username", "password", "auth_group", "cookie"):
            value = getattr(node, field)
            if value is not None:
                out[field] = value
        if node.mtu is not None:
            out["mtu"] = node.mtu


CODEC = SingBoxOpenConnectEndpointCodec()
