from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxEndpointCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _COMMON_KEYS,
    SingBoxCodecError,
    _common_kwargs,
    _optional_bool,
    _optional_string,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _ENDPOINT_COMMON_NODE_FIELDS as _COMMON_NODE_FIELDS,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    TailscaleNode,
)

_TAILSCALE_KEYS = _COMMON_KEYS | frozenset(
    {
        "auth_key",
        "control_url",
        "ephemeral",
        "hostname",
        "accept_routes",
        "exit_node",
        "exit_node_allow_lan_access",
    }
)


class SingBoxTailscaleEndpointCodec(SingBoxEndpointCodec):
    singbox_type = "tailscale"
    protocol = Protocol.TAILSCALE
    node_class = TailscaleNode
    allowed_keys = _TAILSCALE_KEYS
    allowed_node_fields = _COMMON_NODE_FIELDS | frozenset(
        {
            "hostname",
            "auth_key",
            "control_url",
            "ephemeral",
            "accept_routes",
            "exit_node",
            "exit_node_allow_lan_access",
        }
    )
    expected_udp = False

    def parse(self, data: dict[str, Any]) -> TailscaleNode:
        auth_key = _optional_string(data, "auth_key")
        if not auth_key:
            raise SingBoxCodecError(
                "auth_key",
                "Sing-box Tailscale endpoint requires auth_key without local state",
                "parse.singbox.unsupported-protocol-variant",
            )
        exit_node = _optional_string(data, "exit_node")
        if exit_node in {"auto", "auto:any", "none"}:
            raise SingBoxCodecError(
                "exit_node",
                f"Sing-box Tailscale exit_node selector '{exit_node}' is not portable",
                "parse.singbox.unsupported-protocol-variant",
            )
        return TailscaleNode(
            **_common_kwargs(data, udp=False),
            auth_key=auth_key,
            control_url=_optional_string(data, "control_url"),
            ephemeral=_optional_bool(data, "ephemeral"),
            hostname=_optional_string(data, "hostname"),
            accept_routes=_optional_bool(data, "accept_routes"),
            exit_node=exit_node,
            exit_node_allow_lan_access=_optional_bool(
                data, "exit_node_allow_lan_access"
            ),
        )

    def _check_protocol(self, node: Node) -> list[str]:
        assert isinstance(node, TailscaleNode)
        unsupported = []
        if not isinstance(node.auth_key, str) or not node.auth_key:
            unsupported.append("auth_key")
        for field in ("control_url", "hostname", "exit_node"):
            value = getattr(node, field)
            if value is not None and not isinstance(value, str):
                unsupported.append(field)
        if isinstance(node.exit_node, str) and node.exit_node in {
            "auto",
            "auto:any",
            "none",
        }:
            unsupported.append("exit_node")
        for field in ("ephemeral", "accept_routes", "exit_node_allow_lan_access"):
            if type(getattr(node, field)) is not bool:
                unsupported.append(field)
        return unsupported

    def _emit_protocol(self, out: dict[str, Any], node: Node) -> None:
        assert isinstance(node, TailscaleNode)
        out["auth_key"] = node.auth_key
        if node.control_url:
            out["control_url"] = node.control_url
        out["ephemeral"] = node.ephemeral
        if node.hostname:
            out["hostname"] = node.hostname
        out["accept_routes"] = node.accept_routes
        if node.exit_node:
            out["exit_node"] = node.exit_node
        out["exit_node_allow_lan_access"] = node.exit_node_allow_lan_access


CODEC = SingBoxTailscaleEndpointCodec()
