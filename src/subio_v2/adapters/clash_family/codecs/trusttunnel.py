from __future__ import annotations

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._dialects import stash_fields
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
)
from subio_v2.core.nodes import Node, Protocol
from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.protocols.trusttunnel import SPEC


class TrustTunnelCodec(StructuredClashProtocolCodec):
    spec = SPEC

    def stash_lossless_default(self, node: Node, key: str, value: object) -> bool:
        return key == "udp" and value is False

    def normalize_stash(self, data: dict[str, object]) -> dict[str, object]:
        data.setdefault("udp", False)
        return data

    protocol = Protocol.TRUSTTUNNEL
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "trusttunnel"
    dialect_fields = {
        "stash": stash_fields(
            "name",
            "type",
            "server",
            "port",
            "username",
            "password",
            "quic",
            "sni",
            "alpn",
            "skip-cert-verify",
            "server-cert-fingerprint",
            endpoint=False,
        )
    }
    fields = (
        scalar_field("username", default="", emit_policy=EmitPolicy.ALWAYS),
        scalar_field("password", default="", emit_policy=EmitPolicy.ALWAYS),
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

    def _check_mihomo(self, node: Node) -> list[IssueDraft]:
        warnings: list[IssueDraft] = []
        for field, value in (
            ("headers", node.headers),
            ("websocket", node.websocket),
        ):
            if value:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=f"Trust Tunnel field '{field}' is Surge-only",
                        field=field,
                        code="conversion.unconsumed-source-field",
                    )
                )
        return warnings

    def _check_stash(self, node: Node) -> list[IssueDraft]:
        warnings: list[IssueDraft] = []
        for field, value in (
            ("headers", node.headers),
            ("websocket", node.websocket),
        ):
            if value:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
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
                    IssueDraft(
                        severity=IssueSeverity.WARNING,
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
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            f"Trust Tunnel TLS field '{field}' cannot be "
                            "represented by Stash"
                        ),
                        field=f"tls.{field}",
                        code="conversion.unconsumed-source-field",
                    )
                )
        return warnings

    def checker_for_target(self, target: str):
        return {"mihomo": self._check_mihomo, "stash": self._check_stash}[target]


CODEC = TrustTunnelCodec()
