from __future__ import annotations

from typing import Any, Dict

from subio_v2.clash.helpers import (
    assign_extra,
    emit_base,
    emit_smux,
    merge_extra,
    parse_base_fields,
    parse_smux,
)
from subio_v2.model.nodes import Node, Protocol, ShadowsocksNode
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class ShadowsocksDescriptor(ProtocolDescriptor):
    protocol = Protocol.SHADOWSOCKS
    clash_type = "ss"
    node_class = ShadowsocksNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        handled = {
            "cipher",
            "password",
            "plugin",
            "plugin-opts",
            "smux",
            "udp-over-tcp",
            "udp-over-tcp-version",
            "client-fingerprint",
        }
        node = ShadowsocksNode(
            type=Protocol.SHADOWSOCKS,
            cipher=data.get("cipher", "chacha20-ietf-poly1305"),
            password=data.get("password", ""),
            plugin=data.get("plugin"),
            plugin_opts=data.get("plugin-opts"),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, ShadowsocksNode):
            raise TypeError(f"Expected ShadowsocksNode, got {type(node)}")
        base = emit_base(node)
        base.update(
            {
                "cipher": node.cipher,
                "password": node.password,
            }
        )
        if node.plugin:
            base["plugin"] = node.plugin
            if node.plugin_opts:
                base["plugin-opts"] = node.plugin_opts
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, ShadowsocksNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        supported_ciphers = proto_caps.get("ciphers", set())
        if node.cipher and node.cipher not in supported_ciphers:
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"Cipher '{node.cipher}' is not supported by {platform}",
                    field="cipher",
                    suggestion=f"Supported ciphers: {', '.join(sorted(supported_ciphers))}",
                )
            )

        if node.plugin:
            supported_plugins = proto_caps.get("plugins", set())
            if node.plugin not in supported_plugins:
                warnings.append(
                    CapabilityWarning(
                        level=WarningLevel.ERROR,
                        message=f"Plugin '{node.plugin}' is not supported by {platform}",
                        field="plugin",
                        suggestion=(
                            f"Supported plugins: {', '.join(sorted(supported_plugins))}"
                            if supported_plugins
                            else "No plugins supported"
                        ),
                    )
                )

            if node.plugin == "obfs" and node.plugin_opts:
                obfs_mode = node.plugin_opts.get("mode")
                obfs_host = node.plugin_opts.get("host")
                if obfs_mode == "tls" and obfs_host:
                    warnings.append(
                        CapabilityWarning(
                            level=WarningLevel.INFO,
                            message=(
                                f"obfs-host will be ignored when obfs mode is 'tls' on {platform}"
                            ),
                            field="plugin_opts",
                        )
                    )
        return warnings


register(ShadowsocksDescriptor())
