from __future__ import annotations

from collections.abc import Callable
from dataclasses import fields
from typing import Any

from subio_v2.adapters.singbox.codecs._fields import (
    _COMMON_KEYS,
    _ROUTING_MARK_MAX,
    SingBoxCodecError,
    _emit_common,
    _optional_bool,
    _optional_int,
    _optional_string,
    _parse_network,
)
from subio_v2.core.nodes import (
    BaseNode,
    Node,
    Protocol,
    TLSSettings,
)
from subio_v2.core.results import IssueDraft, IssueSeverity

_ENDPOINT_KEYS = frozenset({"server", "server_port"})


_COMMON_NODE_FIELDS = frozenset(
    {
        "name",
        "type",
        "server",
        "port",
        "udp",
        "tfo",
        "mptcp",
        "dialer_proxy",
        "interface_name",
        "routing_mark",
        "record",
    }
)


_MINIMAL_NODE_FIELDS = frozenset({"name", "type", "record"})


class SingBoxOutboundCodec:
    def __init__(
        self,
        singbox_type: str,
        protocol: Protocol,
        node_class: type[BaseNode],
        protocol_keys: frozenset[str],
        allowed_node_fields: frozenset[str],
        *,
        parse_fields: Callable[[dict[str, Any]], dict[str, Any]],
        emit_fields: Callable[[dict[str, Any], Node], None],
        check_fields: Callable[[Node], list[str]] = lambda node: [],
        endpoint: bool = True,
        network: bool = False,
        tcp_only: bool = False,
        force_tls: bool = False,
        common_options: bool = True,
    ):
        self.parse_fields = parse_fields
        self.emit_fields = emit_fields
        self.check_fields = check_fields
        self.singbox_type = singbox_type
        self.protocol = protocol
        self.node_class = node_class
        self.endpoint = endpoint
        self.network = network
        self.tcp_only = tcp_only
        self.force_tls = force_tls
        self.common_options = common_options
        base_keys = _COMMON_KEYS if common_options else frozenset({"type", "tag"})
        self.allowed_keys = base_keys | protocol_keys
        if endpoint:
            self.allowed_keys |= _ENDPOINT_KEYS
        base_node_fields = (
            _COMMON_NODE_FIELDS if common_options else _MINIMAL_NODE_FIELDS
        )
        self.allowed_node_fields = base_node_fields | allowed_node_fields

    @property
    def target_constraints(self) -> dict[str, object]:
        return {}

    def parse(self, data: dict[str, Any]) -> Node:
        tag = data.get("tag")
        if not isinstance(tag, str) or not tag:
            raise SingBoxCodecError(
                "tag",
                "Sing-box outbound field 'tag' must be a non-empty string",
                "parse.singbox.invalid-field",
            )
        routing_mark = data.get("routing_mark")
        if routing_mark is not None and type(routing_mark) is not int:
            raise SingBoxCodecError(
                "routing_mark",
                "String routing marks are not supported",
                "parse.singbox.unsupported-field",
            )
        if routing_mark is not None and not 0 <= routing_mark <= _ROUTING_MARK_MAX:
            raise SingBoxCodecError(
                "routing_mark",
                f"Sing-box field 'routing_mark' must be between 0 and {_ROUTING_MARK_MAX}",
                "parse.singbox.invalid-field",
            )
        kwargs: dict[str, Any] = {
            "name": tag,
            "type": self.protocol,
            "server": _optional_string(data, "server") if self.endpoint else None,
            "port": _optional_int(data, "server_port") if self.endpoint else None,
            "udp": False
            if self.tcp_only
            else (_parse_network(data) if self.network else True),
            "dialer_proxy": _optional_string(data, "detour"),
            "interface_name": _optional_string(data, "bind_interface"),
            "routing_mark": routing_mark,
            "tfo": _optional_bool(data, "tcp_fast_open"),
            "mptcp": _optional_bool(data, "tcp_multi_path"),
        }
        kwargs.update(self.parse_fields(data))
        return self.node_class(**kwargs)

    def check(self, node: Node) -> list[IssueDraft]:
        if not isinstance(node, self.node_class):
            return [
                IssueDraft(
                    IssueSeverity.ERROR,
                    f"Expected {self.node_class.__name__}, got {type(node).__name__}",
                    "type",
                )
            ]
        default = self.node_class(name="__singbox_default__")
        unsupported = []
        for item in fields(node):
            if item.name in self.allowed_node_fields:
                continue
            if getattr(node, item.name) != getattr(default, item.name):
                unsupported.append(item.name)
        if self.tcp_only and node.udp:
            unsupported.append("udp")
        if not self.tcp_only and not self.network and not node.udp:
            unsupported.append("udp")
        tls = getattr(node, "tls", None)
        if isinstance(tls, TLSSettings):
            advanced_tls = (
                "client_fingerprint",
                "reality_opts",
                "ech_opts",
                "certificate",
                "private_key",
                "verify_name",
                "certificate_sha256",
                "client_cert_ref",
            )
            unsupported.extend(
                f"tls.{name}" for name in advanced_tls if getattr(tls, name)
            )
            if self.force_tls and not tls.enabled:
                unsupported.append("tls.enabled")
        if self.common_options and node.routing_mark is not None:
            if type(node.routing_mark) is not int or not (
                0 <= node.routing_mark <= _ROUTING_MARK_MAX
            ):
                unsupported.append("routing_mark")
        unsupported.extend(self.check_fields(node))
        return [
            IssueDraft(
                IssueSeverity.ERROR,
                f"Node field cannot be represented by sing-box: {field}",
                field,
                code="conversion.unsupported-platform-field",
            )
            for field in sorted(set(unsupported))
        ]

    def encode(self, node: Node) -> dict[str, Any]:
        issues = self.check(node)
        if issues:
            issue = issues[0]
            raise SingBoxCodecError(issue.field or "node", issue.message, issue.code)
        out: dict[str, Any] = {"type": self.singbox_type, "tag": node.name}
        if self.endpoint:
            out["server"] = node.server
            out["server_port"] = node.port
        if self.common_options:
            if node.dialer_proxy:
                out["detour"] = node.dialer_proxy
            if node.interface_name:
                out["bind_interface"] = node.interface_name
            if node.routing_mark is not None:
                out["routing_mark"] = node.routing_mark
            if node.tfo:
                out["tcp_fast_open"] = True
            if node.mptcp:
                out["tcp_multi_path"] = True
        if self.network and not node.udp:
            out["network"] = "tcp"
        self.emit_fields(out, node)
        return out


class SingBoxEndpointCodec:
    singbox_type: str
    protocol: Protocol
    node_class: type[BaseNode]
    allowed_keys: frozenset[str]
    allowed_node_fields: frozenset[str]
    expected_udp: bool

    @property
    def target_constraints(self) -> dict[str, object]:
        return {}

    def check(self, node: Node) -> list[IssueDraft]:
        if not isinstance(node, self.node_class):
            return [
                IssueDraft(
                    IssueSeverity.ERROR,
                    f"Expected {self.node_class.__name__}, got {type(node).__name__}",
                    "type",
                )
            ]
        default = self.node_class(name="__singbox_default__")
        unsupported = [
            item.name
            for item in fields(node)
            if item.name not in self.allowed_node_fields
            and getattr(node, item.name) != getattr(default, item.name)
        ]
        if not isinstance(node.name, str) or not node.name:
            unsupported.append("name")
        for field in ("dialer_proxy", "interface_name"):
            value = getattr(node, field)
            if value is not None and not isinstance(value, str):
                unsupported.append(field)
        for field in ("tfo", "mptcp"):
            if type(getattr(node, field)) is not bool:
                unsupported.append(field)
        if node.udp is not self.expected_udp:
            unsupported.append("udp")
        if node.routing_mark is not None and (
            type(node.routing_mark) is not int
            or not 0 <= node.routing_mark <= _ROUTING_MARK_MAX
        ):
            unsupported.append("routing_mark")
        unsupported.extend(self._check_protocol(node))
        return [
            IssueDraft(
                IssueSeverity.ERROR,
                f"Node field cannot be represented by sing-box endpoint: {field}",
                field,
                code="conversion.unsupported-platform-field",
            )
            for field in sorted(set(unsupported))
        ]

    def _check_protocol(self, node: Node) -> list[str]:
        return []

    def encode(self, node: Node) -> dict[str, Any]:
        issues = self.check(node)
        if issues:
            issue = issues[0]
            raise SingBoxCodecError(issue.field or "node", issue.message, issue.code)
        out: dict[str, Any] = {"type": self.singbox_type, "tag": node.name}
        _emit_common(out, node)
        self._emit_protocol(out, node)
        return out

    def _emit_protocol(self, out: dict[str, Any], node: Node) -> None:
        raise NotImplementedError
