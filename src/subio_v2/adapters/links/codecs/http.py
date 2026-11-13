from subio_v2.core.nodes import HttpVariant
from subio_v2.core.results import IssueDraft, IssueSeverity
import urllib.parse

from subio_v2.adapters.links.codecs._base import LinkCodec, format_authority, quote_name
from subio_v2.core.nodes import HttpNode, Node, Protocol


def build(node: Node) -> str:
    assert isinstance(node, HttpNode)
    scheme = "https" if node.tls.enabled else "http"
    userinfo = ""
    if node.username or node.password:
        userinfo = (
            f"{urllib.parse.quote(node.username or '', safe='')}:"
            f"{urllib.parse.quote(node.password or '', safe='')}@"
        )
    return (
        f"{scheme}://{userinfo}{format_authority(node.server, node.port)}"
        f"#{quote_name(node.name)}"
    )


def _check_representation(
    node: Node, proto_caps: dict, platform: str
) -> list[IssueDraft]:
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
            message=f"HTTP TLS options cannot be represented by {platform}: {fields}",
            field=unsupported[0],
        )
    ]


def check(node: Node, constraints, target: str) -> list[IssueDraft]:
    issues = _check_representation(node, constraints, target)
    if node.headers:
        issues.append(
            IssueDraft(
                IssueSeverity.ERROR,
                "HTTP links cannot preserve required headers",
                "headers",
                code="conversion.unsupported-platform-field",
            )
        )
    return issues


CODEC = LinkCodec(
    Protocol.HTTP,
    frozenset({"dae"}),
    build,
    check=check,
    target_constraints={"dae": {"features": {"tls"}}},
)
