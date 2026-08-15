from __future__ import annotations

from typing import Any

from subio_v2.model.nodes import Node, Protocol, ShadowsocksNode
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group


class ShadowsocksDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.SHADOWSOCKS
    clash_type = "ss"
    node_class = ShadowsocksNode
    fields = (
        scalar_field(
            "cipher",
            default="chacha20-ietf-poly1305",
            emit_policy=EmitPolicy.ALWAYS,
            required=True,
        ),
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field("plugin", emit_policy=EmitPolicy.TRUTHY),
        scalar_field(
            "plugin-opts",
            "plugin_opts",
            emit_policy=EmitPolicy.TRUTHY,
            emit_if=lambda node, value: bool(node.plugin),
        ),
        smux_group(),
    )

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
