from __future__ import annotations

import base64
import binascii

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Node, Protocol, ShadowsocksNode
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group


class ShadowsocksDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.SHADOWSOCKS
    clash_dialects = frozenset({"mihomo", "clash", "stash"})
    clash_type = "ss"
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

    def validate(self, node: Node):
        errors = super().validate(node)
        if isinstance(node, ShadowsocksNode) and node.cipher == "none":
            return [error for error in errors if error.field != "password"]
        return errors

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, ShadowsocksNode):
            return []
        warnings: list[IssueDraft] = []
        supported_ciphers = proto_caps.get("ciphers", set())
        if node.cipher and node.cipher not in supported_ciphers:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Cipher '{node.cipher}' is not supported by {platform}",
                    field="cipher",
                    suggestion=f"Supported ciphers: {', '.join(sorted(supported_ciphers))}",
                )
            )

        if platform == "surge":
            if node.cipher == "none":
                pass
            elif not node.password:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message="Shadowsocks password is required for this cipher",
                        field="password",
                    )
                )
            elif node.cipher.startswith("2022-blake3-aes-"):
                expected = 16 if "128" in node.cipher else 32
                try:
                    decoded = base64.b64decode(node.password, validate=True)
                except (binascii.Error, ValueError):
                    decoded = b""
                if len(decoded) != expected:
                    warnings.append(
                        IssueDraft(
                            severity=IssueSeverity.ERROR,
                            message=(
                                f"{node.cipher} requires a base64 key encoding "
                                f"{expected} bytes"
                            ),
                            field="password",
                        )
                    )

        if node.plugin:
            supported_plugins = proto_caps.get("plugins", set())
            if node.plugin not in supported_plugins:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=f"Plugin '{node.plugin}' is not supported by {platform}",
                        field="plugin",
                        suggestion=(
                            f"Supported plugins: {', '.join(sorted(supported_plugins))}"
                            if supported_plugins
                            else "No plugins supported"
                        ),
                    )
                )

        return warnings


DESCRIPTOR = ShadowsocksDescriptor()
