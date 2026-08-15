from __future__ import annotations

from typing import Any

from subio_v2.model.nodes import Node, Protocol, TrustTunnelNode
from subio_v2.protocols import register
from subio_v2.protocols._base import NodeValidationError, StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group, tls_group


class TrustTunnelDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.TRUSTTUNNEL
    clash_type = "trusttunnel"
    node_class = TrustTunnelNode
    fields = (
        scalar_field(
            "username", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        tls_group(
            consumed_keys=(
                "sni",
                "alpn",
                "skip-cert-verify",
                "fingerprint",
                "name-cert-verify",
                "client-fingerprint",
                "ech-opts",
                "certificate",
                "private-key",
            ),
            force_enabled=True,
        ),
        scalar_field("health-check", "health_check", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("quic", default=False, emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "congestion-controller",
            "congestion_controller",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field("cwnd", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("bbr-profile", "bbr_profile", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "max-connections", "max_connections", emit_policy=EmitPolicy.NOT_NONE
        ),
        scalar_field("min-streams", "min_streams", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("max-streams", "max_streams", emit_policy=EmitPolicy.NOT_NONE),
        smux_group(),
    )

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = super().validate(node)
        if not isinstance(node, TrustTunnelNode):
            return errors
        if node.max_streams is not None and (
            node.max_connections is not None or node.min_streams is not None
        ):
            errors.append(
                NodeValidationError(
                    "max_streams",
                    "Trust Tunnel max-streams conflicts with max-connections/min-streams",
                )
            )
        if node.quic and node.websocket:
            errors.append(
                NodeValidationError(
                    "websocket", "Trust Tunnel QUIC and WebSocket modes conflict"
                )
            )
        return errors

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, TrustTunnelNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        if platform == "surge":
            if node.udp:
                warnings.append(
                    CapabilityWarning(
                        level=WarningLevel.ERROR,
                        message="Surge Trust Tunnel does not support UDP",
                        field="udp",
                        code="conversion.unsupported-protocol-variant",
                    )
                )
            for field, value in (
                ("health_check", node.health_check),
                ("congestion_controller", node.congestion_controller),
                ("cwnd", node.cwnd),
                ("bbr_profile", node.bbr_profile),
                ("max_connections", node.max_connections),
                ("min_streams", node.min_streams),
                ("client_fingerprint", node.tls.client_fingerprint),
            ):
                if value:
                    warnings.append(
                        CapabilityWarning(
                            level=WarningLevel.WARNING,
                            message=f"Trust Tunnel field '{field}' is Mihomo-only",
                            field=field,
                            code="conversion.unconsumed-source-field",
                        )
                    )
            for field, value in (
                ("ech_opts", node.tls.ech_opts),
                ("certificate", node.tls.certificate),
                ("private_key", node.tls.private_key),
            ):
                if value:
                    warnings.append(
                        CapabilityWarning(
                            level=WarningLevel.ERROR,
                            message=(
                                f"Trust Tunnel TLS field '{field}' cannot be represented by Surge"
                            ),
                            field=f"tls.{field}",
                            code="conversion.unconsumed-source-field",
                        )
                    )
        elif platform == "clash-meta":
            for field, value in (
                ("headers", node.headers),
                ("websocket", node.websocket),
            ):
                if value:
                    warnings.append(
                        CapabilityWarning(
                            level=WarningLevel.ERROR,
                            message=f"Trust Tunnel field '{field}' is Surge-only",
                            field=field,
                            code="conversion.unconsumed-source-field",
                        )
                    )
        elif platform == "stash":
            for field, value in (
                ("headers", node.headers),
                ("websocket", node.websocket),
            ):
                if value:
                    warnings.append(
                        CapabilityWarning(
                            level=WarningLevel.ERROR,
                            message=f"Trust Tunnel field '{field}' is Surge-only",
                            field=field,
                            code="conversion.unsupported-protocol-variant",
                        )
                    )
            for field, value in (
                ("health_check", node.health_check),
                ("congestion_controller", node.congestion_controller),
                ("cwnd", node.cwnd),
                ("bbr_profile", node.bbr_profile),
                ("max_connections", node.max_connections),
                ("min_streams", node.min_streams),
                ("max_streams", node.max_streams),
                ("client_fingerprint", node.tls.client_fingerprint),
                ("verify_name", node.tls.verify_name),
                ("smux", node.smux.enabled),
            ):
                if value is not None and value is not False:
                    warnings.append(
                        CapabilityWarning(
                            level=WarningLevel.WARNING,
                            message=f"Trust Tunnel field '{field}' is Mihomo-only",
                            field=field,
                            code="conversion.unconsumed-source-field",
                        )
                    )
            for field, value in (
                ("ech_opts", node.tls.ech_opts),
                ("certificate", node.tls.certificate),
                ("private_key", node.tls.private_key),
            ):
                if value:
                    warnings.append(
                        CapabilityWarning(
                            level=WarningLevel.ERROR,
                            message=(
                                f"Trust Tunnel TLS field '{field}' cannot be "
                                "represented by Stash"
                            ),
                            field=f"tls.{field}",
                            code="conversion.unconsumed-source-field",
                        )
                    )
        return warnings


register(TrustTunnelDescriptor())
