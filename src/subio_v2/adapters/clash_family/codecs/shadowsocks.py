from __future__ import annotations

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._dialects import (
    SS_CIPHERS_STASH,
    stash_fields,
)
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
)
from subio_v2.core.nodes import Node, Protocol, ShadowsocksNode
from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.protocols.shadowsocks import SPEC
from subio_v2.protocols.values import SS_CIPHERS_2022, SS_CIPHERS_EXTENDED


class ShadowsocksCodec(StructuredClashProtocolCodec):
    spec = SPEC

    def post_stash_emit(
        self, data: dict[str, object], node: Node
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        options = data.get("plugin-opts")
        if not isinstance(options, dict):
            return data, ()
        source_context = node.source_context
        if source_context is not None and source_context.dialect == "stash":
            return data, ()
        from subio_v2.adapters.clash_family.stash import _PLUGIN_FIELDS

        supported = _PLUGIN_FIELDS.get(str(data.get("plugin")), frozenset())
        dropped: list[str] = []
        for key in tuple(options):
            if key not in supported:
                options.pop(key)
                dropped.append(f"plugin-opts.{key}")
        if not options:
            data.pop("plugin-opts", None)
        return data, tuple(sorted(dropped))

    protocol = Protocol.SHADOWSOCKS
    clash_dialects = frozenset({"mihomo", "clash", "stash"})
    clash_type = "ss"
    dialect_fields = {
        "stash": stash_fields("cipher", "password", "plugin", "plugin-opts")
    }
    target_constraints = {
        "clash": {
            "ciphers": SS_CIPHERS_EXTENDED,
            "plugins": {"obfs", "v2ray-plugin"},
        },
        "mihomo": {
            "ciphers": SS_CIPHERS_EXTENDED | SS_CIPHERS_2022,
            "plugins": {"obfs", "v2ray-plugin", "shadow-tls", "restls"},
            "features": {"smux"},
        },
        "stash": {
            "ciphers": SS_CIPHERS_STASH,
            "plugins": {"obfs", "v2ray-plugin", "shadow-tls"},
        },
    }
    fields = (
        scalar_field(
            "cipher",
            default="chacha20-ietf-poly1305",
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field("password", default="", emit_policy=EmitPolicy.ALWAYS),
        scalar_field("plugin", emit_policy=EmitPolicy.TRUTHY),
        scalar_field(
            "plugin-opts",
            "plugin_opts",
            emit_policy=EmitPolicy.TRUTHY,
            emit_if=lambda node, value: bool(node.plugin),
        ),
        smux_group(),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, ShadowsocksNode):
            return []
        warnings: list[IssueDraft] = []
        if node.udp_port is not None:
            warnings.append(
                IssueDraft(
                    IssueSeverity.ERROR,
                    "This target cannot preserve a separate UDP port",
                    "udp_port",
                    code="conversion.unsupported-platform-field",
                )
            )
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


CODEC = ShadowsocksCodec()
