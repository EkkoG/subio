from __future__ import annotations

from typing import Any, Dict

from subio_v2.clash.helpers import assign_extra, emit_base, merge_extra, parse_base_fields
from subio_v2.model.nodes import Node, Protocol, SSHNode
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class SSHDescriptor(ProtocolDescriptor):
    protocol = Protocol.SSH
    clash_type = "ssh"
    node_class = SSHNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        handled = {
            "username",
            "password",
            "private-key",
            "private-key-passphrase",
            "host-key",
            "host-key-algorithms",
        }
        node = SSHNode(
            type=Protocol.SSH,
            username=data.get("username", ""),
            password=data.get("password"),
            private_key=data.get("private-key"),
            private_key_passphrase=data.get("private-key-passphrase"),
            host_key=data.get("host-key"),
            host_key_algorithms=data.get("host-key-algorithms"),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, SSHNode):
            raise TypeError(f"Expected SSHNode, got {type(node)}")
        base = emit_base(node)
        base["username"] = node.username
        if node.password:
            base["password"] = node.password
        if node.private_key:
            base["private-key"] = node.private_key
        if node.private_key_passphrase:
            base["private-key-passphrase"] = node.private_key_passphrase
        if node.host_key:
            base["host-key"] = node.host_key
        if node.host_key_algorithms:
            base["host-key-algorithms"] = node.host_key_algorithms
        return merge_extra(base, node)

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, SSHNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        supported_auth = proto_caps.get("auth_methods", set())
        if node.private_key and "private_key" not in supported_auth:
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"SSH private key authentication is not supported by {platform}",
                    field="private_key",
                )
            )
        if node.password and "password" not in supported_auth:
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"SSH password authentication is not supported by {platform}",
                    field="password",
                )
            )
        return warnings


register(SSHDescriptor())
