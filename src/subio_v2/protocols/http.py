from __future__ import annotations

from subio_v2.core.nodes import HttpNode, HttpVariant, Node, Protocol
from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import EmitPolicy, scalar_field, tls_group
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.HTTP,
    node_class=HttpNode,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset({"headers", "max_streams", "password", "tls", "username", "variant"}),
)


class HttpCodec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.HTTP
    clash_dialects = frozenset({"mihomo", "clash", "stash"})
    clash_type = "http"
    dialect_fields = {
        "stash": stash_fields("username", "password", "headers", tls=True)
    }
    target_constraints = {
        "clash": {"features": {"tls"}},
        "mihomo": {"features": {"tls"}},
        "stash": {"features": {"tls"}},
    }
    fields = (
        scalar_field("username", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("password", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("headers", emit_policy=EmitPolicy.TRUTHY),
        tls_group(
            consumed_keys=(
                "tls",
                "sni",
                "skip-cert-verify",
                "fingerprint",
                "client-fingerprint",
                "name-cert-verify",
                "alpn",
                "certificate",
                "private-key",
            )
        ),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, HttpNode):
            return []
        if node.variant == HttpVariant.H2_CONNECT:
            if "h2-connect" not in proto_caps.get("features", set()):
                return [
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=f"HTTP/2 CONNECT is not supported by {platform}",
                        field="variant",
                    )
                ]
            if node.udp and "connect-udp" not in proto_caps.get("features", set()):
                return [
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=f"CONNECT-UDP is not supported by {platform}",
                        field="udp",
                    )
                ]

        if not node.tls or not node.tls.enabled:
            return []

        if "tls" not in proto_caps.get("features", set()):
            return [
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"HTTP TLS is not supported by {platform}",
                    field="tls",
                )
            ]
        if platform not in {"dae", "v2rayn"}:
            return []

        unsupported: list[str] = []
        if node.tls.server_name and node.tls.server_name != node.server:
            unsupported.append("sni")
        if node.tls.skip_cert_verify:
            unsupported.append("skip-cert-verify")
        if node.tls.alpn:
            unsupported.append("alpn")
        if node.tls.certificate_sha256:
            unsupported.append("fingerprint")
        if node.tls.client_fingerprint:
            unsupported.append("client-fingerprint")
        if node.tls.verify_name:
            unsupported.append("name-cert-verify")
        if node.tls.reality_opts:
            unsupported.append("reality-opts")
        if node.tls.ech_opts:
            unsupported.append("ech-opts")
        if node.tls.certificate or node.tls.private_key:
            unsupported.append("client-certificate")
        if not unsupported:
            return []
        fields = ", ".join(unsupported)
        return [
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=(
                    f"HTTP TLS options cannot be represented by {platform}: {fields}"
                ),
                field=unsupported[0],
            )
        ]


CODEC = HttpCodec()
